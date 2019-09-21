-------------------------------------------------------------------------------
--  Copyright (c) 2019 Daniel King
--
--  Permission is hereby granted, free of charge, to any person obtaining a
--  copy of this software and associated documentation files (the "Software"),
--  to deal in the Software without restriction, including without limitation
--  the rights to use, copy, modify, merge, publish, distribute, sublicense,
--  and/or sell copies of the Software, and to permit persons to whom the
--  Software is furnished to do so, subject to the following conditions:
--
--  The above copyright notice and this permission notice shall be included in
--  all copies or substantial portions of the Software.
--
--  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
--  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
--  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
--  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
--  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
--  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
--  DEALINGS IN THE SOFTWARE.
-------------------------------------------------------------------------------
with Ada.Unchecked_Conversion;
with DW1000.Types;             use DW1000.Types;
with Interfaces;               use Interfaces;

package IEEE802154.MAC
with SPARK_Mode => On
is

   --  Min/Max length of the MAC header (excluding Header IEs).
   Min_MHR_Length : constant := 2;
   Max_MHR_Length : constant := 37;

   --  Min/Max length of the Auxiliary Security Header
   Min_Aux_Security_Header_Length : constant := 0;
   Max_Aux_Security_Header_Length : constant := 14;

   ------------------------
   --  Frame Type Field  --
   ------------------------
   --  Ref. 7.2.1.1 of IEEE 802.15.4-2015

   type Frame_Type_Field is
     (Beacon,
      Data,
      Ack,
      MAC_Command,
      Reserved,
      Multipurpose,
      Frak,
      Extended)
     with Size => 3;

   for Frame_Type_Field use
     (Beacon       => 2#000#,
      Data         => 2#001#,
      Ack          => 2#010#,
      MAC_Command  => 2#011#,
      Reserved     => 2#100#,
      Multipurpose => 2#101#,
      Frak         => 2#110#,
      Extended     => 2#111#);

   ------------------------------
   --  Security Enabled Field  --
   ------------------------------
   --  Ref. 7.2.1.2 of IEEE 802.15.4-2015

   type Security_Enabled_Field is
     (Disabled,
      Enabled)
     with Size => 1;

   for Security_Enabled_Field use
     (Disabled => 0,
      Enabled  => 1);

   ---------------------------
   --  Frame Pending Field  --
   ---------------------------
   --  Ref. 7.2.1.3 of IEEE 802.15.4-2015

   type Frame_Pending_Field is
     (Not_Pending,
      Pending)
     with Size => 1;

   for Frame_Pending_Field use
     (Not_Pending => 0,
      Pending     => 1);

   --------------------------
   --  Ack Required Field  --
   --------------------------
   --  Ref. 7.2.1.4 of IEEE 802.15.4-2015

   type Ack_Required_Field is
     (Not_Required,
      Required)
     with Size => 1;

   for Ack_Required_Field use
     (Not_Required => 0,
      Required     => 1);

   --------------------------
   --  PAN ID Compression  --
   --------------------------
   --  Ref. 7.2.1.5 of IEEE 802.15.4-2015

   type PAN_ID_Compression_Field is
     (Not_Compressed,
      Compressed)
     with Size => 1;

   for PAN_ID_Compression_Field use
     (Not_Compressed => 0,
      Compressed     => 1);

   -----------------------------------
   --  Sequence Number Suppression  --
   -----------------------------------
   --  Ref. 7.2.1.6 of IEEE 802.15.4-2015

   type Seq_Number_Suppression_Field is
     (Not_Suppressed,
      Suppressed)
     with Size => 1;

   for Seq_Number_Suppression_Field use
     (Not_Suppressed => 0,
      Suppressed     => 1);

   ------------------------------------------
   --  Information Elements Present Field  --
   ------------------------------------------
   --  Ref. 7.2.1.7 of IEEE 802.15.4-2015

   type IE_Present_Field is
     (Not_Present,
      Present)
     with Size => 1;

   for IE_Present_Field use
     (Not_Present => 0,
      Present     => 1);

   ------------------------------------------------
   --  Destination/Source Addressing Mode Field  --
   ------------------------------------------------
   --  Ref. 7.2.1.8 of IEEE 802.15.4-2015

   type Address_Mode_Field is
     (Not_Present,
      Reserved,
      Short,
      Extended)
     with Size => 2;

   for Address_Mode_Field use
     (Not_Present => 2#00#,
      Reserved    => 2#01#,
      Short       => 2#10#,
      Extended    => 2#11#);

   ----------------------------------------
   --  Destination/Source Address Field  --
   ----------------------------------------
   --  Ref. 7.2.4 of IEEE 802.15.4-2015

   type Extended_Address_Field is new Interfaces.Unsigned_64;

   type Short_Address_Field is new Interfaces.Unsigned_16;

   type Variant_Address (Mode : Address_Mode_Field := Not_Present) is
      record
         case Mode is
            when Not_Present | Reserved =>
               null;

            when Short =>
               Short_Address : Short_Address_Field;

            when Extended =>
               Extended_Address : Extended_Address_Field;
         end case;
      end record;

   ---------------------------
   --  Frame Version Field  --
   ---------------------------
   --  Ref. 7.2.1.9 of IEEE 802.15.4-2015

   type Frame_Version_Field is
     (IEEE_802_15_4_2003,
      IEEE_802_15_4_2006,
      IEEE_802_15_4,
      Reserved)
     with Size => 2;

   for Frame_Version_Field use
     (IEEE_802_15_4_2003 => 2#00#,
      IEEE_802_15_4_2006 => 2#01#,
      IEEE_802_15_4      => 2#10#,
      Reserved           => 2#11#);

   -----------------------------
   --  Sequence Number Field  --
   -----------------------------
   --  Ref. 7.2.2 of IEEE 802.15.4-2015

   type Sequence_Number_Field is new Interfaces.Unsigned_8;

   type Variant_Sequence_Number
     (Suppression : Seq_Number_Suppression_Field := Suppressed) is
      record
         case Suppression is
            when Suppressed =>
               null;

            when Not_Suppressed =>
               Number : Sequence_Number_Field;
         end case;
      end record;

   --------------------
   --  PAN ID Field  --
   --------------------
   --  Ref. 7.2.3 of IEEE 802.15.4-2015

   type PAN_ID_Field is new Interfaces.Unsigned_16;

   type Variant_PAN_ID (Present : Boolean := False) is
      record
         case Present is
            when False =>
               null;

            when True =>
               PAN_ID : PAN_ID_Field;
         end case;
      end record;

   ---------------------------
   --  Frame Control Field  --
   ---------------------------
   --  Ref. 7.2.1 of IEEE 802.15.4-2015

   --  Note that Multipurpose and Extended frame control field formats
   --  are NOT supported in this implementation.

   type Frame_Control_Field is
      record
         Frame_Type         : Frame_Type_Field;
         Security_Enabled   : Security_Enabled_Field;
         Frame_Pending      : Frame_Pending_Field;
         AR                 : Ack_Required_Field;
         PAN_ID_Compression : PAN_ID_Compression_Field;
         Reserved           : DW1000.Types.Bits_1;
         SN_Suppression     : Seq_Number_Suppression_Field;
         IE_Present         : IE_Present_Field;
         Dest_Address_Mode  : Address_Mode_Field;
         Frame_Version      : Frame_Version_Field;
         Src_Address_Mode   : Address_Mode_Field;
      end record
     with Size => 16;

   for Frame_Control_Field use
      record
         Frame_Type         at 0 range  0 ..  2;
         Security_Enabled   at 0 range  3 ..  3;
         Frame_Pending      at 0 range  4 ..  4;
         AR                 at 0 range  5 ..  5;
         PAN_ID_Compression at 0 range  6 ..  6;
         Reserved           at 0 range  7 ..  7;
         SN_Suppression     at 0 range  8 ..  8;
         IE_Present         at 0 range  9 ..  9;
         Dest_Address_Mode  at 0 range 10 .. 11;
         Frame_Version      at 0 range 12 .. 13;
         Src_Address_Mode   at 0 range 14 .. 15;
      end record;

   ----------------------------
   --  Security Level Field  --
   ----------------------------
   --  Ref. 9.4.1.1 of IEEE 802.15.4-2015

   type Security_Level_Field is range 0 .. 7
     with Size => 3;

   ---------------------------------
   --  Key Identifier Mode Field  --
   ---------------------------------
   --  Ref. 9.4.1.2 of IEEE 802.15.4-2015

   type Key_ID_Mode_Field is range 0 .. 3
     with Size => 2;

   ---------------------------------------
   --  Frame Counter Suppression Field  --
   ---------------------------------------
   --  Ref. 9.4.1.3 of IEEE 802.15.4-2015

   type Frame_Counter_Suppression_Field is
     (Not_Suppressed,
      Suppressed)
     with Size => 1;

   for Frame_Counter_Suppression_Field use
     (Not_Suppressed => 0,
      Suppressed     => 1);

   --------------------------
   --  ASN In Nonce Field  --
   --------------------------
   --  Ref. 9.4.1.4 of IEEE 802.15.4-2015

   type Nonce_Source_Field is
     (From_Frame_Counter,
      From_ASN)
     with Size => 1;

   for Nonce_Source_Field use
     (From_Frame_Counter => 0,
      From_ASN           => 1);

   ------------------------------
   --  Security Control Field  --
   ------------------------------
   --  Ref. 9.4.1 of IEEE 802.15.4-2015

   type Security_Control_Field is
      record
         Security_Level : Security_Level_Field;
         Key_ID_Mode    : Key_ID_Mode_Field;
         FC_Suppression : Frame_Counter_Suppression_Field;
         Nonce_Source   : Nonce_Source_Field;
         Reserved       : DW1000.Types.Bits_1;
      end record
     with Size => 8;

   for Security_Control_Field use
      record
         Security_Level at 0 range 0 .. 2;
         Key_ID_Mode    at 0 range 3 .. 4;
         FC_Suppression at 0 range 5 .. 5;
         Nonce_Source   at 0 range 6 .. 6;
         Reserved       at 0 range 7 .. 7;
      end record;

   ---------------------------
   --  Frame Counter Field  --
   ---------------------------
   --  Ref. 9.4.2 of IEEE 802.15.4-2015

   type Frame_Counter_Field is new Interfaces.Unsigned_32;

   type Variant_Frame_Counter
     (Suppression : Frame_Counter_Suppression_Field := Suppressed) is
      record
         case Suppression is
            when Suppressed =>
               null;

            when Not_Suppressed =>
               Frame_Counter : Frame_Counter_Field;
         end case;
      end record;

   ----------------------------
   --  Key Identifier Field  --
   ----------------------------
   --  Ref. 9.4.3 of IEEE 802.15.4-2015

   type Key_Source_Field is new DW1000.Types.Byte_Array
     with Dynamic_Predicate => Key_Source_Field'Length in 0 | 4 | 8;

   type Key_Index_Field is range 0 .. 255
     with Size => 8;

   --  Presence of Key Index and Key Source fields depends on the Key ID Mode.
   --  Refer to Table 9-7 of IEEE 802.15.4-2015.

   type Variant_Key_ID (Mode : Key_ID_Mode_Field := 0) is
      record
         case Mode is
            when 0 =>
               null;

            when 1 .. 3 =>
               Key_Index : Key_Index_Field;

               case Mode is
                  when 0 | 1 =>
                     null;

                  when 2 =>
                     Key_Source_4 : Key_Source_Field (1 .. 4);

                  when 3 =>
                     Key_Source_8 : Key_Source_Field (1 .. 8);
               end case;
         end case;
      end record;

   ---------------------------------
   --  Auxiliary Security Header  --
   ---------------------------------
   --  Ref 9.4 of IEEE 802.15.4-2015

   type Variant_Aux_Security_Header
     (Security_Enabled : Security_Enabled_Field := Disabled) is
      record
         case Security_Enabled is
            when Disabled =>
               null;

            when Enabled =>
               Security_Level : Security_Level_Field;
               ASN_In_Nonce   : Nonce_Source_Field;
               Frame_Counter  : Variant_Frame_Counter;
               Key_ID         : Variant_Key_ID;
         end case;
      end record;

   ------------------
   --  MAC Header  --
   ------------------
   --  Ref. 7.2 of IEEE 802.15.4-2015

   type MAC_Header is
      record
         --  Frame Control Fields.
         --  Note that some fields are in the variant part of other fields.
         Frame_Type         : Frame_Type_Field;
         Frame_Pending      : Frame_Pending_Field;
         AR                 : Ack_Required_Field;
         PAN_ID_Compression : PAN_ID_Compression_Field;
         IE_Present         : IE_Present_Field;
         Frame_Version      : Frame_Version_Field;

         --  Other fields
         Sequence_Number     : Variant_Sequence_Number;
         Destination_PAN_ID  : Variant_PAN_ID;
         Destination_Address : Variant_Address;
         Source_PAN_ID       : Variant_PAN_ID;
         Source_Address      : Variant_Address;
         Aux_Security_Header : Variant_Aux_Security_Header;
      end record;

   ------------------------------
   --  Is_Valid_Configuration  --
   ------------------------------

   function Is_Valid_Configuration
     (Destination_Address_Mode   : in Address_Mode_Field;
      Source_Address_Mode        : in Address_Mode_Field;
      Destination_PAN_ID_Present : in Boolean;
      Source_PAN_ID_Present      : in Boolean) return Boolean
     with Global => null;
   --  Checks if the given source/destination address and PAN IDs are a
   --  valid configuration according to Table 7-2 of IEEE 802.15.4-2015.

   ------------------------------
   --  Get_PAN_ID_Compression  --
   ------------------------------

   function Get_PAN_ID_Compression
     (Destination_Address_Mode   : in Address_Mode_Field;
      Source_Address_Mode        : in Address_Mode_Field;
      Destination_PAN_ID_Present : in Boolean;
      Source_PAN_ID_Present      : in Boolean) return PAN_ID_Compression_Field
     with Global => null,
     Pre => Is_Valid_Configuration (Destination_Address_Mode,
                                    Source_Address_Mode,
                                    Destination_PAN_ID_Present,
                                    Source_PAN_ID_Present);
   --  Get the value of the PAN ID Compression field for the specified
   --  source/destination address and PAN ID presence configuration.
   --
   --  Note that this function follows the rules for frame version 2#10#
   --  (i.e. IEEE_802_15_4) as specified in Table 7-2 of IEEE 802.15.4-2015

   --------------------------------
   --  Is_Source_PAN_ID_Present  --
   --------------------------------

   function Is_Source_PAN_ID_Present
     (Destination_Address_Mode : in Address_Mode_Field;
      Source_Address_Mode      : in Address_Mode_Field;
      PAN_ID_Compression       : in PAN_ID_Compression_Field) return Boolean
     with Global => null;

   -------------------------------------
   --  Is_Destination_PAN_ID_Present  --
   -------------------------------------

   function Is_Destination_PAN_ID_Present
     (Destination_Address_Mode : in Address_Mode_Field;
      Source_Address_Mode      : in Address_Mode_Field;
      PAN_ID_Compression       : in PAN_ID_Compression_Field) return Boolean
     with Global => null;

   --------------
   --  Encode  --
   --------------

   procedure Encode (MHR    : in     MAC_Header;
                     Buffer : in out DW1000.Types.Byte_Array;
                     Length :    out Natural)
     with Global => null,
     Depends => (Buffer =>+ MHR,
                 Length =>  MHR),
     Pre => (Buffer'Length >= Max_MHR_Length
             and MHR.Frame_Version /= Reserved
             and Is_Valid_Configuration
               (Destination_Address_Mode   => MHR.Destination_Address.Mode,
                Source_Address_Mode        => MHR.Source_Address.Mode,
                Destination_PAN_ID_Present => MHR.Destination_PAN_ID.Present,
                Source_PAN_ID_Present      => MHR.Source_PAN_ID.Present)),
     Post => (Length <= Buffer'Length
              and (Length in Min_MHR_Length .. Max_MHR_Length));
   --  Encode a MAC header into a byte array.

   --------------
   --  Decode  --
   --------------

   type Decode_Result is
     (Success,         --  Decode was successful
      End_Of_Buffer,   --  Error: End of buffer was reached during decode
      Reserved_Field); --  Error: A reserved value was encountered.

   procedure Decode (Buffer : in     DW1000.Types.Byte_Array;
                     MHR    :    out MAC_Header;
                     Length :    out Natural;
                     Result :    out Decode_Result)
     with Global => null,
     Pre => Buffer'Length > 0,
     Post =>
       (Length <= Buffer'Length
        and Length <= Max_MHR_Length
        and
          (if Result = Success then
             (MHR.Frame_Version /= Reserved
              and MHR.Destination_Address.Mode /= Reserved
              and MHR.Source_Address.Mode /= Reserved
              and Is_Valid_Configuration
                (Destination_Address_Mode   => MHR.Destination_Address.Mode,
                 Source_Address_Mode        => MHR.Source_Address.Mode,
                 Destination_PAN_ID_Present => MHR.Destination_PAN_ID.Present,
                 Source_PAN_ID_Present      => MHR.Source_PAN_ID.Present))));
   --  Decode a MAC header from a byte array buffer.
   --
   --  If the decode was successful then the source/destination addresses
   --  and PAN IDs are guaranteed to be a valid configuration.

   -------------------
   --  Conversions  --
   -------------------

   subtype Byte_Array_2 is DW1000.Types.Byte_Array (1 .. 2);
   subtype Byte_Array_4 is DW1000.Types.Byte_Array (1 .. 4);
   subtype Byte_Array_8 is DW1000.Types.Byte_Array (1 .. 8);

   --  These subprograms convert certain field types to and from their
   --  byte array representation.
   --
   --  These are used for encoding and decoding operations.

   function Convert is new Ada.Unchecked_Conversion
     (Source => Frame_Control_Field,
      Target => Byte_Array_2);

   function Convert is new Ada.Unchecked_Conversion
     (Source => Byte_Array_2,
      Target => Frame_Control_Field);

   function Convert is new Ada.Unchecked_Conversion
     (Source => Security_Control_Field,
      Target => Bits_8);

   function Convert is new Ada.Unchecked_Conversion
     (Source => Bits_8,
      Target => Security_Control_Field);

   function Convert (PAN_ID : in PAN_ID_Field) return Byte_Array_2
     with Inline,
     Global => null;

   function Convert (Bytes : in Byte_Array_2) return PAN_ID_Field
     with Inline,
     Global => null;

   function Convert (Address : in Short_Address_Field) return Byte_Array_2
     with Inline,
     Global => null;

   function Convert (Bytes : in Byte_Array_2) return Short_Address_Field
     with Inline,
     Global => null;

   function Convert (FC : in Frame_Counter_Field) return Byte_Array_4
     with Inline,
     Global => null;

   function Convert (Bytes : in Byte_Array_4) return Frame_Counter_Field
     with Inline,
     Global => null;

   function Convert (Address : in Extended_Address_Field) return Byte_Array_8
     with Inline,
     Global => null;

   function Convert (Bytes : in Byte_Array_8) return Extended_Address_Field
     with Inline,
     Global => null;

private

   -----------------------------------------
   --  PAN ID Configuration Validity LUT  --
   -----------------------------------------

   Valid_PAN_ID_Configurations : constant array (Address_Mode_Field,
                                                 Address_Mode_Field,
                                                 Boolean,
                                                 Boolean) of Boolean :=
   --              |                    |Destination| Source  |
   --  Destination |    Source          |  PAN ID   | PAN ID  |
   --    Address   |    Address         | Present?  |Present? | Valid?
     (Not_Present => (Not_Present      => (False  => (False  => True,    --  Row 1
                                                      True   => False),
                                           True   => (False  => True,    --  Row 2
                                                      True   => False)),
                      Reserved         => (others => (others => False)),
                      Short | Extended => (False  => (False  => True,    --  Row 6
                                                      True   => True),   --  Row 5
                                           True   => (others => False))),
      Reserved    => (others           => (others => (others => False))),
      Short       => (Not_Present      => (False  => (False  => True,    --  Row 4
                                                      True   => False),
                                           True   => (False  => True,    --  Row 3
                                                      True   => False)),
                      Reserved         => (others => (others => False)),
                      Short            => (False  => (others => False),
                                           True   => (False  => True,    --  Row 14
                                                      True   => True)),  --  Row 9
                      Extended         => (False  => (False  => False,
                                                      True   => False),
                                           True   => (False  => True,    --  Row 12
                                                      True   => True))), --  Row 10
      Extended    => (Not_Present      => (False  => (False  => True,    --  Row 4
                                                      True   => False),
                                           True   => (False  => True,    --  Row 3
                                                      True   => False)),
                      Reserved         => (others => (others => False)),
                      Short            => (False  => (others => False),
                                           True   => (False  => True,    --  Row 13
                                                      True   => True)),  --  Row 11
                      Extended         => (False  => (False  => True,    --  Row 8
                                                      True   => False),
                                           True   => (False  => True,    --  Row 7
                                                      True   => False))));
   --  This look-up table captures the set of valid configurations
   --  for all possible Source/Destination Address and PAN ID combinations.
   --
   --  Only the set of configurations listed in Table 7-2 of IEEE 802.15.4-2015
   --  are permitted (marked as True in the last column of this table).
   --  All other combinations are not allowed.
   --
   --  The entries in this table are annotated with the corresponding row
   --  number from Table 7-2.

   ----------------------------------
   --  Source PAN ID Presence LUT  --
   ----------------------------------

   Source_PAN_ID_Presence : constant array (Address_Mode_Field,
                                            Address_Mode_Field,
                                            PAN_ID_Compression_Field) of Boolean :=
   --              |               |                  |  Source
   --  Destination |    Source     |     PAN ID       |  PAN ID
   --    Address   |    Address    |   Compression    | Present?
     (Not_Present => (Not_Present => (Not_Compressed => False,    --  Row 1
                                      Compressed     => False),   --  Row 2
                      Reserved    => (others         => False),
                      Short       => (Not_Compressed => True,     --  Row 5
                                      Compressed     => False),   --  Row 6
                      Extended    => (Not_Compressed => True,     --  Row 5
                                      Compressed     => False)),  --  Row 6
      Reserved    => (others      => (others         => False)),
      Short       => (Not_Present => (Not_Compressed => False,    --  Row 3
                                      Compressed     => False),   --  Row 4
                      Reserved    => (others         => False),
                      Short       => (Not_Compressed => True,     --  Row 9
                                      Compressed     => False),   --  Row 14
                      Extended    => (Not_Compressed => True,     --  Row 10
                                      Compressed     => False)),  --  Row 12
      Extended    => (Not_Present => (Not_Compressed => False,    --  Row 3
                                      Compressed     => False),   --  Row 4
                      Reserved    => (others         => False),
                      Short       => (Not_Compressed => True,     --  Row 11
                                      Compressed     => False),   --  Row 13
                      Extended    => (Not_Compressed => False,    --  Row 7
                                      Compressed     => False))); --  Row 8
   --  This look-up table determines when the source PAN ID field is present
   --  in the encoded MAC header.
   --
   --  The circumstances when the source PAN ID is present is documented in
   --  Table 7-2 of IEEE 802.15.4-2015.

   ---------------------------------------
   --  Destination PAN ID Presence LUT  --
   ---------------------------------------

   Destination_PAN_ID_Presence : constant array (Address_Mode_Field,
                                                 Address_Mode_Field,
                                                 PAN_ID_Compression_Field) of Boolean :=
   --              |               |                  |  Dest.
   --  Destination |    Source     |     PAN ID       |  PAN ID
   --    Address   |    Address    |   Compression    | Present?
     (Not_Present => (Not_Present => (Not_Compressed => False,    --  Row 1
                                      Compressed     => True),    --  Row 2
                      Reserved    => (others         => False),
                      Short       => (Not_Compressed => False,    --  Row 5
                                      Compressed     => False),   --  Row 6
                      Extended    => (Not_Compressed => False,    --  Row 5
                                      Compressed     => False)),  --  Row 6
      Reserved    => (others      => (others         => False)),
      Short       => (Not_Present => (Not_Compressed => True,     --  Row 3
                                      Compressed     => False),   --  Row 4
                      Reserved    => (others         => False),
                      Short       => (Not_Compressed => True,     --  Row 9
                                      Compressed     => True),    --  Row 14
                      Extended    => (Not_Compressed => True,     --  Row 10
                                      Compressed     => True)),   --  Row 12
      Extended    => (Not_Present => (Not_Compressed => True,     --  Row 3
                                      Compressed     => False),   --  Row 4
                      Reserved    => (others         => False) ,
                      Short       => (Not_Compressed => True,     --  Row 11
                                      Compressed     => True),    --  Row 13
                      Extended    => (Not_Compressed => True,     --  Row 7
                                      Compressed     => False))); --  Row 8
   --  This look-up table determines when the destination PAN ID field is
   --  present in the encoded MAC header.
   --
   --  The circumstances when the destination PAN ID is present is documented
   --  in Table 7-2 of IEEE 802.15.4-2015.

   ------------------------------
   --  Is_Valid_Configuration  --
   ------------------------------

   function Is_Valid_Configuration
     (Destination_Address_Mode   : in Address_Mode_Field;
      Source_Address_Mode        : in Address_Mode_Field;
      Destination_PAN_ID_Present : in Boolean;
      Source_PAN_ID_Present      : in Boolean) return Boolean is
     (Valid_PAN_ID_Configurations (Destination_Address_Mode,
                                   Source_Address_Mode,
                                   Destination_PAN_ID_Present,
                                   Source_PAN_ID_Present));

   ------------------------------
   --  Get_PAN_ID_Compression  --
   ------------------------------

   --  Refer to Table 7-2 of IEEE 802.15.4-2015 for the rules for when the
   --  PAN ID compression is set.

   function Get_PAN_ID_Compression
     (Destination_Address_Mode   : in Address_Mode_Field;
      Source_Address_Mode        : in Address_Mode_Field;
      Destination_PAN_ID_Present : in Boolean;
      Source_PAN_ID_Present      : in Boolean) return PAN_ID_Compression_Field is
     (if Source_PAN_ID_Present then Not_Compressed
      elsif Destination_PAN_ID_Present then
        (if (Destination_Address_Mode = Extended
             and Source_Address_Mode = Extended)
         then Not_Compressed

         elsif (Destination_Address_Mode = Not_Present
                xor Source_Address_Mode = Not_Present)
         then Not_Compressed

         else Compressed)

      else
        (if (Destination_Address_Mode = Extended
             and Source_Address_Mode = Extended)
         then Compressed

         elsif (Destination_Address_Mode = Not_Present
                and Source_Address_Mode = Not_Present)
         then Not_Compressed

         else Compressed)
     );

   --------------------------------
   --  Is_Source_PAN_ID_Present  --
   --------------------------------

   function Is_Source_PAN_ID_Present
     (Destination_Address_Mode : in Address_Mode_Field;
      Source_Address_Mode      : in Address_Mode_Field;
      PAN_ID_Compression       : in PAN_ID_Compression_Field) return Boolean is
     (Source_PAN_ID_Presence (Destination_Address_Mode,
                              Source_Address_Mode,
                              PAN_ID_Compression));

   -------------------------------------
   --  Is_Destination_PAN_ID_Present  --
   -------------------------------------

   function Is_Destination_PAN_ID_Present
     (Destination_Address_Mode : in Address_Mode_Field;
      Source_Address_Mode      : in Address_Mode_Field;
      PAN_ID_Compression       : in PAN_ID_Compression_Field) return Boolean is
     (Destination_PAN_ID_Presence (Destination_Address_Mode,
                                   Source_Address_Mode,
                                   PAN_ID_Compression));

   -------------------
   --  Conversions  --
   -------------------

   function Convert (PAN_ID : in PAN_ID_Field) return Byte_Array_2
   is (Byte_Array_2'(Bits_8 (Unsigned_16 (PAN_ID) and 16#FF#),
                     Bits_8 (Shift_Right (Unsigned_16 (PAN_ID), 8) and 16#FF#)));

   function Convert (Bytes : in Byte_Array_2) return PAN_ID_Field
   is (PAN_ID_Field (Bytes (1))
       or PAN_ID_Field (Shift_Left (Unsigned_16 (Bytes (2)), 8)));

   function Convert (Address : in Short_Address_Field) return Byte_Array_2
   is (Byte_Array_2'(Bits_8 (Unsigned_16 (Address) and 16#FF#),
                     Bits_8 (Shift_Right (Unsigned_16 (Address), 8) and 16#FF#)));

   function Convert (Bytes : in Byte_Array_2) return Short_Address_Field
   is (Short_Address_Field (Bytes (1))
       or Short_Address_Field (Shift_Left (Unsigned_16 (Bytes (2)), 8)));

   function Convert (FC : in Frame_Counter_Field) return Byte_Array_4
   is (Byte_Array_4'(Bits_8 (Unsigned_32 (FC) and 16#FF#),
                     Bits_8 (Shift_Right (Unsigned_32 (FC),  8) and 16#FF#),
                     Bits_8 (Shift_Right (Unsigned_32 (FC), 16) and 16#FF#),
                     Bits_8 (Shift_Right (Unsigned_32 (FC), 24) and 16#FF#)));

   function Convert (Bytes : in Byte_Array_4) return Frame_Counter_Field
   is (Frame_Counter_Field (Bytes (1))
       or Frame_Counter_Field (Shift_Left (Unsigned_32 (Bytes (2)),  8))
       or Frame_Counter_Field (Shift_Left (Unsigned_32 (Bytes (3)), 16))
       or Frame_Counter_Field (Shift_Left (Unsigned_32 (Bytes (4)), 24)));

   function Convert (Address : in Extended_Address_Field) return Byte_Array_8
   is (Byte_Array_8'(Bits_8 (Unsigned_64 (Address) and 16#FF#),
                     Bits_8 (Shift_Right (Unsigned_64 (Address),  8) and 16#FF#),
                     Bits_8 (Shift_Right (Unsigned_64 (Address), 16) and 16#FF#),
                     Bits_8 (Shift_Right (Unsigned_64 (Address), 24) and 16#FF#),
                     Bits_8 (Shift_Right (Unsigned_64 (Address), 32) and 16#FF#),
                     Bits_8 (Shift_Right (Unsigned_64 (Address), 40) and 16#FF#),
                     Bits_8 (Shift_Right (Unsigned_64 (Address), 48) and 16#FF#),
                     Bits_8 (Shift_Right (Unsigned_64 (Address), 56) and 16#FF#)));

   function Convert (Bytes : in Byte_Array_8) return Extended_Address_Field
   is (Extended_Address_Field (Bytes (1))
       or Extended_Address_Field (Shift_Left (Unsigned_64 (Bytes (2)),  8))
       or Extended_Address_Field (Shift_Left (Unsigned_64 (Bytes (3)), 16))
       or Extended_Address_Field (Shift_Left (Unsigned_64 (Bytes (4)), 24))
       or Extended_Address_Field (Shift_Left (Unsigned_64 (Bytes (5)), 32))
       or Extended_Address_Field (Shift_Left (Unsigned_64 (Bytes (6)), 40))
       or Extended_Address_Field (Shift_Left (Unsigned_64 (Bytes (7)), 48))
       or Extended_Address_Field (Shift_Left (Unsigned_64 (Bytes (8)), 56)));

end IEEE802154.MAC;
