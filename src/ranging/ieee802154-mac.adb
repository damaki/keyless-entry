package body IEEE802154.MAC
with SPARK_Mode => On
is

   ----------------------------
   --  Encode_PAN_ID (spec)  --
   ----------------------------

   procedure Encode_PAN_ID (PAN_ID : in     Variant_PAN_ID;
                            Buffer : in out DW1000.Types.Byte_Array;
                            Offset : in out Natural)
     with Inline,
     Global => null,
     Depends => (Buffer =>+ (Offset, PAN_ID),
                 Offset =>+ PAN_ID),
     Pre => (Buffer'Length >= 2
             and then Offset <= Buffer'Length - 2),
     Contract_Cases => (PAN_ID.Present => Offset = Offset'Old + 2,
                        others         => (Offset = Offset'Old
                                           and Buffer = Buffer'Old));

   ----------------------------
   --  Encode_PAN_ID (body)  --
   ----------------------------

   procedure Encode_PAN_ID (PAN_ID : in     Variant_PAN_ID;
                            Buffer : in out DW1000.Types.Byte_Array;
                            Offset : in out Natural) is

      Pos : constant DW1000.Types.Index := Buffer'First + Offset;

   begin
      if PAN_ID.Present then
         Buffer (Pos .. Pos + 1) := Convert (PAN_ID.PAN_ID);
         Offset := Offset + 2;
      end if;
   end Encode_PAN_ID;

   -----------------------------
   --  Encode_Address (spec)  --
   -----------------------------

   procedure Encode_Address (Address : in     Variant_Address;
                             Buffer  : in out DW1000.Types.Byte_Array;
                             Offset  : in out Natural)
     with Inline,
     Global => null,
     Depends => (Buffer =>+ (Offset, Address),
                 Offset =>+ (Offset, Address)),
     Pre => (Buffer'Length >= 8
             and then Offset <= Buffer'Length - 8
             and then Address.Mode /= Reserved),
     Contract_Cases => (Address.Mode = Extended => Offset = Offset'Old + 8,
                        Address.Mode = Short    => Offset = Offset'Old + 2,
                        others                  => (Offset = Offset'Old
                                                    and Buffer = Buffer'Old));

   -----------------------------
   --  Encode_Address (body)  --
   -----------------------------

   procedure Encode_Address (Address : in     Variant_Address;
                             Buffer  : in out DW1000.Types.Byte_Array;
                             Offset  : in out Natural) is
      Pos : constant DW1000.Types.Index := Buffer'First + Offset;

   begin
      case Address.Mode is
         when Extended =>
            Buffer (Pos .. Pos + 7) := Convert (Address.Extended_Address);
            Offset := Offset + 8;

         when Short =>
            Buffer (Pos .. Pos + 1) := Convert (Address.Short_Address);
            Offset := Offset + 2;

         when Reserved =>
            --  Unreachable (unless precondition is violated)
            raise Program_Error;

         when Not_Present =>
            null;
      end case;
   end Encode_Address;

   -----------------------------------------
   --  Encode_Aux_Security_Header (spec)  --
   -----------------------------------------

   procedure Encode_Aux_Security_Header
     (ASH    : in     Variant_Aux_Security_Header;
      Buffer : in out DW1000.Types.Byte_Array;
      Offset : in out Natural)
     with Inline,
     Global => null,
     Depends => (Buffer =>+ (Offset, ASH),
                 Offset =>+ (Offset, ASH)),
     Pre => (Buffer'Length >= Max_Aux_Security_Header_Length
             and then Offset <= Buffer'Length - Max_Aux_Security_Header_Length),
     Post => (Offset in Offset'Old .. Offset'Old + Max_Aux_Security_Header_Length);

   -----------------------------------------
   --  Encode_Aux_Security_Header (body)  --
   -----------------------------------------

   procedure Encode_Aux_Security_Header
     (ASH    : in     Variant_Aux_Security_Header;
      Buffer : in out DW1000.Types.Byte_Array;
      Offset : in out Natural) is

      Pos : DW1000.Types.Index := Buffer'First + Offset;

   begin
      if ASH.Security_Enabled = Enabled then
         --  Encode the Security Control field
         Buffer (Pos) :=
           Convert (Security_Control_Field'
                      (Security_Level => ASH.Security_Level,
                       Key_ID_Mode    => ASH.Key_ID.Mode,
                       FC_Suppression => ASH.Frame_Counter.Suppression,
                       Nonce_Source   => ASH.ASN_In_Nonce,
                       Reserved       => 0));

         Pos    := Pos    + 1;
         Offset := Offset + 1;

         --  Encode the Frame Counter (if not suppressed)
         if ASH.Frame_Counter.Suppression = Not_Suppressed then
            Buffer (Pos .. Pos + 3) := Convert (ASH.Frame_Counter.Frame_Counter);

            Pos    := Pos    + 4;
            Offset := Offset + 4;
         end if;

         --  Encode the Key ID field (variable length)
         case ASH.Key_ID.Mode is
            when 0 =>
               null;

            when 1 =>
               Buffer (Pos) := Bits_8 (ASH.Key_ID.Key_Index);

               Offset := Offset + 1;

            when 2 =>
               Buffer (Pos) := Bits_8 (ASH.Key_ID.Key_Index);
               Buffer (Pos .. Pos + 3) := Byte_Array (ASH.Key_ID.Key_Source_4);

               Offset := Offset + 5;

            when 3 =>
               Buffer (Pos) := Bits_8 (ASH.Key_ID.Key_Index);
               Buffer (Pos .. Pos + 7) := Byte_Array (ASH.Key_ID.Key_Source_8);

               Offset := Offset + 9;
         end case;
      end if;
   end Encode_Aux_Security_Header;

   --------------
   --  Encode  --
   --------------

   procedure Encode (MHR    : in     MAC_Header;
                     Buffer : in out DW1000.Types.Byte_Array;
                     Length :    out Natural) is
      PAN_ID_Compression    : PAN_ID_Compression_Field;
      Include_Source_PAN_ID : Boolean := MHR.Source_PAN_ID.Present;

   begin

      --  Determine whether or not the PAN ID compression field needs to be
      --  set. Refer to Section 7.2.1.5 of IEEE 802.15.4-2015 for a description
      --  of the rules.
      case MHR.Frame_Version is
         when IEEE_802_15_4_2003 | IEEE_802_15_4_2006 =>
            --  If both destination and source addressing information is present,
            --  the MAC sublayer shall compare the destination and source PAN
            --  identifiers. If the PAN IDs are identical, the PAN ID Compression
            --  field shall be set to one, and the Source PAN ID field shall be
            --  omitted from the transmitted frame. If the PAN IDs are different,
            --  the PAN ID Compression field shall be set to zero, and both
            --  Destination PAN ID field and Source PAN ID fields shall be
            --  included in the transmitted frame.
            if (MHR.Destination_PAN_ID.Present
                and MHR.Source_PAN_ID.Present
                and MHR.Destination_Address.Mode /= Not_Present
                and MHR.Source_Address.Mode /= Not_Present)
            then
               if MHR.Source_PAN_ID.PAN_ID = MHR.Destination_PAN_ID.PAN_ID then
                  PAN_ID_Compression    := Compressed;
                  Include_Source_PAN_ID := False;
               else
                  PAN_ID_Compression := Not_Compressed;
               end if;

            else
               PAN_ID_Compression := Not_Compressed;
            end if;

         when IEEE_802_15_4 =>
            PAN_ID_Compression := Get_PAN_ID_Compression
              (Destination_Address_Mode   => MHR.Destination_Address.Mode,
               Source_Address_Mode        => MHR.Source_Address.Mode,
               Destination_PAN_ID_Present => MHR.Destination_PAN_ID.Present,
               Source_PAN_ID_Present      => MHR.Source_PAN_ID.Present);

         when Reserved =>
            --  Unreachable (unless precondition is violated)
            raise Program_Error;
      end case;


      --  Encode the Frame Control field
      Buffer (Buffer'First .. Buffer'First + 1) :=
        Convert (Frame_Control_Field'
                   (Frame_Type         => MHR.Frame_Type,
                    Security_Enabled   => MHR.Aux_Security_Header.Security_Enabled,
                    Frame_Pending      => MHR.Frame_Pending,
                    AR                 => MHR.AR,
                    PAN_ID_Compression => PAN_ID_Compression,
                    Reserved           => 0,
                    SN_Suppression     => MHR.Sequence_Number.Suppression,
                    IE_Present         => MHR.IE_Present,
                    Dest_Address_Mode  => MHR.Destination_Address.Mode,
                    Frame_Version      => MHR.Frame_Version,
                    Src_Address_Mode   => MHR.Source_Address.Mode));

      Length := 2;

      pragma Assert (Length = 2);

      --  Encode the sequence number
      if MHR.Sequence_Number.Suppression = Not_Suppressed then
         Buffer (Buffer'First + Length) := Bits_8 (MHR.Sequence_Number.Number);

         Length := Length + 1;
      end if;

      pragma Assert (Length in 2 .. 3);

      --  Encode the destination PAN ID
      Encode_PAN_ID (PAN_ID => MHR.Destination_PAN_ID,
                     Buffer => Buffer,
                     Offset => Length);

      pragma Assert (Length in 2 .. 5);

      --  Encode the destination address
      Encode_Address (Address => MHR.Destination_Address,
                      Buffer  => Buffer,
                      Offset  => Length);

      pragma Assert (Length in 2 .. 13);

      --  Encode the source PAN ID
      if Include_Source_PAN_ID then
         Encode_PAN_ID (PAN_ID => MHR.Source_PAN_ID,
                        Buffer => Buffer,
                        Offset => Length);
      end if;

      pragma Assert (Length in 2 .. 15);

      --  Encode the source address
      Encode_Address (Address => MHR.Source_Address,
                      Buffer  => Buffer,
                      Offset  => Length);

      pragma Assert (Length in 2 .. 23);

      Encode_Aux_Security_Header (ASH    => MHR.Aux_Security_Header,
                                  Buffer => Buffer,
                                  Offset => Length);

   end Encode;

end IEEE802154.MAC;
