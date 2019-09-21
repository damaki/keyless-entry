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
   --  Decode_Frame_Control_Field (spec)  --
   -----------------------------------------

   procedure Decode_Frame_Control_Field
     (Buffer        : in     DW1000.Types.Byte_Array;
      Frame_Control :    out Frame_Control_Field;
      Result        :    out Decode_Result)
     with Inline,
     Global => null,
     Depends => (Frame_Control => Buffer,
                 Result        => Buffer),
     Post => (if Result = Success then
                (Frame_Control.Frame_Version /= Reserved
                 and Frame_Control.Dest_Address_Mode /= Reserved
                 and Frame_Control.Src_Address_Mode /= Reserved
                 and Buffer'Length >= 2));

   -------------------------------------------
   --  Decode_Sequence_Number_Field (spec)  --
   -------------------------------------------

   procedure Decode_Sequence_Number_Field
     (Buffer          : in     DW1000.Types.Byte_Array;
      Offset          : in out Natural;
      Sequence_Number :    out Variant_Sequence_Number;
      Result          :    out Decode_Result)
     with Inline,
     Global => null,
     Depends => (Sequence_Number => (Buffer, Offset),
                 Result          => (Buffer, Offset),
                 Offset          =>+ Buffer),
     Pre => not Sequence_Number'Constrained,
     Post => (if Result = Success
              then (Offset = Offset'Old + 1 and Offset <= Buffer'Length)
              else Offset = Offset'Old);

   ----------------------------------
   --  Decode_PAN_ID_Field (spec)  --
   ----------------------------------

   procedure Decode_PAN_ID_Field
     (Buffer : in     DW1000.Types.Byte_Array;
      Offset : in out Natural;
      PAN_ID :    out Variant_PAN_ID;
      Result :    out Decode_Result)
     with Inline,
     Global => null,
     Depends => (PAN_ID => (Buffer, Offset),
                 Result => (Buffer, Offset),
                 Offset =>+ Buffer),
     Pre => not PAN_ID'Constrained,
     Post => (if Result = Success
              then (Offset = Offset'Old + 2
                    and Offset <= Buffer'Length
                    and PAN_ID.Present)
              else Offset = Offset'Old);

   --------------------------------------------
   --  Decode_Extended_Address_Field (spec)  --
   --------------------------------------------

   procedure Decode_Extended_Address_Field
     (Buffer  : in     DW1000.Types.Byte_Array;
      Offset  : in out Natural;
      Address :    out Variant_Address;
      Result  :    out Decode_Result)
     with Inline,
     Global => null,
     Depends => (Address => (Buffer, Offset),
                 Result => (Buffer, Offset),
                 Offset =>+ Buffer),
     Pre => not Address'Constrained,
     Post => (if Result = Success
                then (Offset = Offset'Old + 8
                      and Offset <= Buffer'Length
                      and Address.Mode = Extended)
              else Offset = Offset'Old);

   -----------------------------------------
   --  Decode_Short_Address_Field (spec)  --
   -----------------------------------------

   procedure Decode_Short_Address_Field
     (Buffer  : in     DW1000.Types.Byte_Array;
      Offset  : in out Natural;
      Address :    out Variant_Address;
      Result  :    out Decode_Result)
     with Inline,
     Global => null,
     Depends => (Address => (Buffer, Offset),
                 Result => (Buffer, Offset),
                 Offset =>+ Buffer),
     Pre => not Address'Constrained,
     Post => (if Result = Success
                then (Offset = Offset'Old + 2
                      and Offset <= Buffer'Length
                      and Address.Mode = Short)
              else Offset = Offset'Old);

   -----------------------------------------
   --  Decode_Aux_Security_Header (spec)  --
   -----------------------------------------

   procedure Decode_Aux_Security_Header
     (Buffer : in     DW1000.Types.Byte_Array;
      Offset : in out Natural;
      ASH    :    out Variant_Aux_Security_Header;
      Result :    out Decode_Result)
     with Inline,
     Global => null,
     Depends => (ASH    => (Buffer, Offset),
                 Result => (Buffer, Offset),
                 Offset =>+ Buffer),
     Pre => not ASH'Constrained,
     Post => (if Result = Success
                then (Offset > Offset'Old
                      and Offset - Offset'Old <= Max_Aux_Security_Header_Length
                      and Offset <= Buffer'Length
                      and ASH.Security_Enabled = Enabled));

   --------------------------------------------
   --  Decode_Security_Control_Field (spec)  --
   --------------------------------------------

   procedure Decode_Security_Control_Field
     (Buffer : in     DW1000.Types.Byte_Array;
      Offset : in out Natural;
      SC     :    out Security_Control_Field;
      Result :    out Decode_Result)
     with Inline,
     Global => null,
     Depends => (SC     => (Buffer, Offset),
                 Result => (Buffer, Offset),
                 Offset =>+ Buffer),
     Post => (if Result = Success
              then (Offset = Offset'Old + 1 and Offset <= Buffer'Length)
              else Offset = Offset'Old);

   -----------------------------------------
   --  Decode_Frame_Counter_Field (spec)  --
   -----------------------------------------

   procedure Decode_Frame_Counter_Field
     (Buffer : in     DW1000.Types.Byte_Array;
      Offset : in out Natural;
      FC     :    out Variant_Frame_Counter;
      Result :    out Decode_Result)
     with Inline,
     Global => null,
     Depends => (FC     => (Buffer, Offset),
                 Result => (Buffer, Offset),
                 Offset =>+ Buffer),
     Pre => not FC'Constrained,
     Post => (if Result = Success
              then (Offset = Offset'Old + 4
                    and Offset <= Buffer'Length
                    and FC.Suppression = Not_Suppressed)
              else Offset = Offset'Old and FC.Suppression = Suppressed);

   ----------------------------------
   --  Decode_Key_ID_Field (spec)  --
   ----------------------------------

   procedure Decode_Key_ID_Field
     (Buffer : in     DW1000.Types.Byte_Array;
      Mode   : in     Key_ID_Mode_Field;
      Offset : in out Natural;
      Key_ID :    out Variant_Key_ID;
      Result :    out Decode_Result)
     with Inline,
     Global => null,
     Depends => (Key_ID => (Buffer, Mode, Offset),
                 Result => (Buffer, Mode, Offset),
                 Offset =>+ (Buffer, Mode)),
     Pre => not Key_ID'Constrained,
     Post => (if Result = Success
                then Key_ID.Mode = Mode and Offset <= Buffer'Length
                else Offset = Offset'Old),
     Contract_Cases =>
       (Mode = 0 => Offset = Offset'Old,
        Mode = 1 => (if Result = Success then Offset = Offset'Old + 1),
        Mode = 2 => (if Result = Success then Offset = Offset'Old + 5),
        Mode = 3 => (if Result = Success then Offset = Offset'Old + 9));

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

   --------------
   --  Decode  --
   --------------

   procedure Decode (Buffer : in     DW1000.Types.Byte_Array;
                     MHR    :    out MAC_Header;
                     Length :    out Natural;
                     Result :    out Decode_Result) is

      Frame_Control : Frame_Control_Field;

   begin
      Length := 0;

      --  Initialise the MAC header to some default values
      MHR := (Frame_Type          => Frame_Type_Field'First,
              Frame_Pending       => Not_Pending,
              AR                  => Not_Required,
              PAN_ID_Compression  => Not_Compressed,
              IE_Present          => Not_Present,
              Frame_Version       => Frame_Version_Field'First,
              Sequence_Number     => (Suppression => Suppressed),
              Destination_PAN_ID  => (Present => False),
              Destination_Address => (Mode => Not_Present),
              Source_PAN_ID       => (Present => False),
              Source_Address      => (Mode => Not_Present),
              Aux_Security_Header => (Security_Enabled => Disabled));

      Decode_Frame_Control_Field (Buffer        => Buffer,
                                  Frame_Control => Frame_Control,
                                  Result        => Result);

      --  Decode the Sequence Number (if present)
      if Result = Success then
         MHR.Frame_Type         := Frame_Control.Frame_Type;
         MHR.Frame_Pending      := Frame_Control.Frame_Pending;
         MHR.AR                 := Frame_Control.AR;
         MHR.PAN_ID_Compression := Frame_Control.PAN_ID_Compression;
         MHR.IE_Present         := Frame_Control.IE_Present;
         MHR.Frame_Version      := Frame_Control.Frame_Version;

         Length := 2;

         pragma Assert (Length <= Buffer'Length);

         if Frame_Control.SN_Suppression = Not_Suppressed then
            Decode_Sequence_Number_Field (Buffer          => Buffer,
                                          Offset          => Length,
                                          Sequence_Number => MHR.Sequence_Number,
                                          Result          => Result);
         end if;
      end if;

      pragma Assert (Length <= 3);
      pragma Assert (Length <= Buffer'Length);
      pragma Assert (if Result = Success then Length >= 2);

      --  Decode the Destination PAN ID field (if present)
      if Result = Success then
         if Is_Destination_PAN_ID_Present
           (Destination_Address_Mode => Frame_Control.Dest_Address_Mode,
            Source_Address_Mode      => Frame_Control.Src_Address_Mode,
            PAN_ID_Compression       => Frame_Control.PAN_ID_Compression)
         then
            Decode_PAN_ID_Field (Buffer => Buffer,
                                 Offset => Length,
                                 PAN_ID => MHR.Destination_PAN_ID,
                                 Result => Result);
         end if;
      end if;

      pragma Assert (Length <= 5);
      pragma Assert (Length <= Buffer'Length);
      pragma Assert (if Result = Success then Length >= 2);

      --  Decode the Destination Address field (if present)
      if Result = Success then
         case Frame_Control.Dest_Address_Mode is
            when Extended =>
               Decode_Extended_Address_Field (Buffer  => Buffer,
                                              Offset  => Length,
                                              Address => MHR.Destination_Address,
                                              Result  => Result);

            when Short =>
               Decode_Short_Address_Field (Buffer  => Buffer,
                                           Offset  => Length,
                                           Address => MHR.Destination_Address,
                                           Result  => Result);

            when Reserved =>
               raise Program_Error; --  Unreachable

            when Not_Present =>
               null;
         end case;

         pragma Assert (if Result = Success
                        then MHR.Destination_Address.Mode = Frame_Control.Dest_Address_Mode);
      end if;

      pragma Assert (Length <= 13);
      pragma Assert (Length <= Buffer'Length);
      pragma Assert (if Result = Success then Length >= 2);

      --  Decode the Source PAN ID field (if present)
      if Result = Success then
         if Is_Source_PAN_ID_Present
           (Destination_Address_Mode => Frame_Control.Dest_Address_Mode,
            Source_Address_Mode      => Frame_Control.Src_Address_Mode,
            PAN_ID_Compression       => Frame_Control.PAN_ID_Compression)
         then
            Decode_PAN_ID_Field (Buffer => Buffer,
                                 Offset => Length,
                                 PAN_ID => MHR.Source_PAN_ID,
                                 Result => Result);
         end if;
      end if;

      pragma Assert (Length <= 15);
      pragma Assert (Length <= Buffer'Length);
      pragma Assert (if Result = Success then Length >= 2);

      --  Decode the Source Address field (if present)
      if Result = Success then
         case Frame_Control.Src_Address_Mode is
            when Extended =>
               Decode_Extended_Address_Field (Buffer  => Buffer,
                                              Offset  => Length,
                                              Address => MHR.Source_Address,
                                              Result  => Result);

            when Short =>
               Decode_Short_Address_Field (Buffer  => Buffer,
                                           Offset  => Length,
                                           Address => MHR.Source_Address,
                                           Result  => Result);

            when Reserved =>
               raise Program_Error; --  Unreachable

            when Not_Present =>
               null;
         end case;

         pragma Assert (if Result = Success
                        then MHR.Source_Address.Mode = Frame_Control.Src_Address_Mode);
      end if;

      pragma Assert (Length <= 23);
      pragma Assert (Length <= Buffer'Length);
      pragma Assert (if Result = Success then Length >= 2);

   end Decode;

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

   -----------------------------------------
   --  Decode_Frame_Control_Field (body)  --
   -----------------------------------------

   Null_Frame_Control : constant Frame_Control_Field :=
     (Frame_Type         => Frame_Type_Field'First,
      Security_Enabled   => Disabled,
      Frame_Pending      => Not_Pending,
      AR                 => Not_Required,
      PAN_ID_Compression => Not_Compressed,
      Reserved           => 0,
      SN_Suppression     => Not_Suppressed,
      IE_Present         => Not_Present,
      Dest_Address_Mode  => Not_Present,
      Frame_Version      => Frame_Version_Field'First,
      Src_Address_Mode   => Not_Present);

   procedure Decode_Frame_Control_Field
     (Buffer        : in     DW1000.Types.Byte_Array;
      Frame_Control :    out Frame_Control_Field;
      Result        :    out Decode_Result) is

   begin

      if Buffer'Length < 2 then
         Frame_Control := Null_Frame_Control;
         Result        := End_Of_Buffer;

      else
         Frame_Control := Convert (Buffer (Buffer'First .. Buffer'First + 1));

         if (Frame_Control.Frame_Version = Reserved
             or Frame_Control.Dest_Address_Mode = Reserved
             or Frame_Control.Src_Address_Mode = Reserved)
         then
            Result := Reserved_Field;
         else
            Result := Success;
         end if;
      end if;
   end Decode_Frame_Control_Field;

   -------------------------------------------
   --  Decode_Sequence_Number_Field (body)  --
   -------------------------------------------

   procedure Decode_Sequence_Number_Field
     (Buffer          : in     DW1000.Types.Byte_Array;
      Offset          : in out Natural;
      Sequence_Number :    out Variant_Sequence_Number;
      Result          :    out Decode_Result) is
   begin
      if Offset >= Buffer'Length then
         Sequence_Number := (Suppression => Suppressed);
         Result := End_Of_Buffer;

      else
         Sequence_Number :=
           (Suppression => Not_Suppressed,
            Number      => Sequence_Number_Field (Buffer (Buffer'First + Offset)));

         Offset := Offset + 1;
         Result := Success;
      end if;
   end Decode_Sequence_Number_Field;

   ----------------------------------
   --  Decode_PAN_ID_Field (body)  --
   ----------------------------------

   procedure Decode_PAN_ID_Field
     (Buffer : in     DW1000.Types.Byte_Array;
      Offset : in out Natural;
      PAN_ID :    out Variant_PAN_ID;
      Result :    out Decode_Result) is

      Pos : DW1000.Types.Index;

   begin
      if Buffer'Length < 2 or else Offset > Buffer'Length - 2 then
         PAN_ID := (Present => False);
         Result := End_Of_Buffer;

      else
         Pos := Buffer'First + Offset;

         PAN_ID := (Present => True,
                    PAN_ID  => Convert (Buffer (Pos .. Pos + 1)));

         Offset := Offset + 2;
         Result := Success;
      end if;
   end Decode_PAN_ID_Field;

   --------------------------------------------
   --  Decode_Extended_Address_Field (body)  --
   --------------------------------------------

   procedure Decode_Extended_Address_Field
     (Buffer  : in     DW1000.Types.Byte_Array;
      Offset  : in out Natural;
      Address :    out Variant_Address;
      Result  :    out Decode_Result) is

      Pos : DW1000.Types.Index;

   begin
      if Buffer'Length < 8 or else Offset > Buffer'Length - 8 then
         Address := (Mode => Not_Present);
         Result := End_Of_Buffer;

      else
         Pos := Buffer'First + Offset;

         Address := (Mode             => Extended,
                     Extended_Address => Convert (Buffer (Pos .. Pos + 7)));

         Offset := Offset + 8;
         Result := Success;
      end if;
   end Decode_Extended_Address_Field;

   -----------------------------------------
   --  Decode_Short_Address_Field (body)  --
   -----------------------------------------

   procedure Decode_Short_Address_Field
     (Buffer  : in     DW1000.Types.Byte_Array;
      Offset  : in out Natural;
      Address :    out Variant_Address;
      Result  :    out Decode_Result) is

      Pos : DW1000.Types.Index;

   begin
      if Buffer'Length < 2 or else Offset > Buffer'Length - 2 then
         Address := (Mode => Not_Present);
         Result := End_Of_Buffer;

      else
         Pos := Buffer'First + Offset;

         Address := (Mode          => Short,
                     Short_Address => Convert (Buffer (Pos .. Pos + 1)));

         Offset := Offset + 2;
         Result := Success;
      end if;
   end Decode_Short_Address_Field;

   -----------------------------------------
   --  Decode_Aux_Security_Header (body)  --
   -----------------------------------------

   procedure Decode_Aux_Security_Header
     (Buffer : in     DW1000.Types.Byte_Array;
      Offset : in out Natural;
      ASH    :    out Variant_Aux_Security_Header;
      Result :    out Decode_Result) is

      Initial_Offset : constant Natural := Offset with Ghost;

      Security_Control : Security_Control_Field;

   begin
      Decode_Security_Control_Field (Buffer => Buffer,
                                     Offset => Offset,
                                     SC     => Security_Control,
                                     Result => Result);

      if Result = Success then
         pragma Assert (Offset = Initial_Offset + 1);

         ASH := (Security_Enabled => Enabled,
                 Security_Level   => Security_Control.Security_Level,
                 ASN_In_Nonce     => Security_Control.Nonce_Source,
                 Frame_Counter    => (Suppression => Suppressed),
                 Key_ID           => (Mode => 0));

         if Security_Control.FC_Suppression = Not_Suppressed then
            Decode_Frame_Counter_Field (Buffer => Buffer,
                                        Offset => Offset,
                                        FC     => ASH.Frame_Counter,
                                        Result => Result);
         end if;
      else
         ASH := (Security_Enabled => Disabled);
      end if;

      pragma Assert (Offset >= Initial_Offset);
      pragma Assert (if Result = Success then Offset - Initial_Offset in 1 .. 5);
      pragma Assert (if Result = Success then Offset <= Buffer'Length);

      if Result = Success then
         Decode_Key_ID_Field (Buffer => Buffer,
                              Mode   => Security_Control.Key_ID_Mode,
                              Offset => Offset,
                              Key_ID => ASH.Key_ID,
                              Result => Result);
      end if;

      pragma Assert (Offset >= Initial_Offset);
      pragma Assert (if Result = Success then Offset - Initial_Offset in 1 .. 14);
      pragma Assert (if Result = Success then Offset <= Buffer'Length);

   end Decode_Aux_Security_Header;

   --------------------------------------------
   --  Decode_Security_Control_Field (body)  --
   --------------------------------------------

   procedure Decode_Security_Control_Field
     (Buffer : in     DW1000.Types.Byte_Array;
      Offset : in out Natural;
      SC     :    out Security_Control_Field;
      Result :    out Decode_Result) is
   begin
      if Buffer'Length < 1 or else Offset > Buffer'Length - 1 then
         SC := (Security_Level => 0,
                Key_ID_Mode    => 0,
                FC_Suppression => Not_Suppressed,
                Nonce_Source   => From_Frame_Counter,
                Reserved       => 0);
         Result := End_Of_Buffer;

      else
         SC := Convert (Buffer (Buffer'First));

         Offset := Offset + 1;
         Result := Success;
      end if;
   end Decode_Security_Control_Field;

   -----------------------------------------
   --  Decode_Frame_Counter_Field (body)  --
   -----------------------------------------

   procedure Decode_Frame_Counter_Field
     (Buffer : in     DW1000.Types.Byte_Array;
      Offset : in out Natural;
      FC     :    out Variant_Frame_Counter;
      Result :    out Decode_Result) is

      Pos : DW1000.Types.Index;

   begin
      if Buffer'Length < 4 or else Offset > Buffer'Length - 4 then
         FC     := (Suppression => Suppressed);
         Result := End_Of_Buffer;

      else
         Pos := Buffer'First + Offset;

         FC := (Suppression   => Not_Suppressed,
                Frame_Counter => Convert (Buffer (Pos .. Pos + 3)));

         Offset := Offset + 4;
         Result := Success;
      end if;
   end Decode_Frame_Counter_Field;

   ----------------------------------
   --  Decode_Key_ID_Field (body)  --
   ----------------------------------

   procedure Decode_Key_ID_Field
     (Buffer : in     DW1000.Types.Byte_Array;
      Mode   : in     Key_ID_Mode_Field;
      Offset : in out Natural;
      Key_ID :    out Variant_Key_ID;
      Result :    out Decode_Result) is

      Pos : DW1000.Types.Index;

   begin
      case Mode is
         when 0 =>
            Key_ID := (Mode => 0);
            if Offset > Buffer'Length then
               Result := End_Of_Buffer;
            else
               Result := Success;
            end if;

         when 1 =>
            if Buffer'Length < 1 or else Offset > Buffer'Length - 1 then
               Key_ID := (Mode => 0);
               Result := End_Of_Buffer;

            else
               Pos := Buffer'First + Offset;

               Key_ID := (Mode      => 1,
                          Key_Index => Key_Index_Field (Buffer (Pos)));

               Offset := Offset + 1;
               Result := Success;
            end if;

         when 2 =>
            if Buffer'Length < 5 or else Offset > Buffer'Length - 5 then
               Key_ID := (Mode => 0);
               Result := End_Of_Buffer;

            else
               Pos := Buffer'First + Offset;

               Key_ID := (Mode         => 2,
                          Key_Index    => Key_Index_Field (Buffer (Pos)),
                          Key_Source_4 => Key_Source_Field (Buffer (Pos + 1 .. Pos + 4)));

               Offset := Offset + 5;
               Result := Success;
            end if;

         when 3 =>
            if Buffer'Length < 9 or else Offset > Buffer'Length - 9 then
               Key_ID := (Mode => 0);
               Result := End_Of_Buffer;

            else
               Pos := Buffer'First + Offset;

               Key_ID := (Mode         => 3,
                          Key_Index    => Key_Index_Field (Buffer (Pos)),
                          Key_Source_8 => Key_Source_Field (Buffer (Pos + 1 .. Pos + 8)));

               Offset := Offset + 9;
               Result := Success;
            end if;
      end case;
   end Decode_Key_ID_Field;

end IEEE802154.MAC;
