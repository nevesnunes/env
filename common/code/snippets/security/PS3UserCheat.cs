// Patch PS3UserCheat Cheat to an ELF File
// 1. Decrypt EBOOT.BIN to EBOOT.ELF
// 2. Provide PATCH.TXT with the following Format (From PS3 Cheats Editor)
// Example PATCH.TXT
//00002000 0002A878 33FE034C
// Another Example of PATCH.TXT
//00002000 010AF534 00000000
//00002000 010AF538 00000000
//00002000 010AF53C 00000000
//00002000 010AF540 00000000
// 3. Run this Code
// 4. Rencrypt EBOOT.KDSBest.ELF to EBOOT.BIN
// 5. Replace EBOOT.BIN of your game with the new one

// Sorry I couldn't provide a One Click Tool I lack in time
// the 0000c001 patches are button mapping for cheat pkgs, since we fixed patch it this isn't supported.
// Example Tales of Grace F Move Fast Speed (Press []) is the following PATCH.TXT
//00002000 007DF6FC 3F800000
//0000C001 00000000 00000080
//00002000 007DF6FC 3FE00000
// If you don't want to patch the speed the PATCH.TXT you provide
//00002000 007DF6FC 3F800000
// If you want constant faster speed you provide
//00002000 007DF6FC 3FE00000
// It reads the following way
// 00002000 = Patch Mem﻿ory (Eboot)
// 0000C001 = Button Event
// Look how easy
// If nothing is pressed
// {
//00002000 007DF6FC 3F800000 => Patch Memory At 007DF6FC to 3F800000
// }
//0000C001 00000000 00000080 => else If(Button Event(00000080)) => 00000080 = []
// {
//00002000 007DF6FC 3FE00000 => Patch Memory At 007DF6FC to 3FE00000
// }

// Why I write this tool
// I provided the patches by hand
// 1. Load ELF in IDA
// 2. Check bytes at Address
// 3. Search Bytes from IDA (Which can parse the elf header and knows the exact locations) in Hex Editor
// 4. Patch Bytes by hand
// 5. ....

// Why is this tool written like bullshit
// I don't have the mood to write it clean

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace Patch_ELF_PS3UserCheat
{
    class Program
    {
        public struct ELFLocation
        {
            public uint Offset;
            public uint OffsetFile;
            public uint Size;
        }

        public struct Patch
        {
            public uint Offset;
            public uint PatchValue;
        }

        public static uint byteToUInt(byte[]
                {
                return byteToUInt(b, 0);
                }

                public static uint byteToUInt(byte[] b, int offset)
                {
                uint a = (uint)b[offset] << 24;
                a |= (uint)b[offset + 1] << 16;
                a |= (uint)b[offset + 2] << 8;
                a |= (uint)b[offset + 3] << 0;
                return a;
                }

                public static byte[] uintToByte(uint i)
                {
                byte[] b = new byte[4];
                b[0] = (byte)((i >> 24) & 0xFF);
                b[1] = (byte)((i >> 16) & 0xFF);
                b[2] = (byte)((i >> 8) & 0xFF);
                b[3] = (byte)((i) & 0xFF);
                return b;
                }

        public static int LoadElfPHDR(BinaryReader br, List Elf, uint phdr_offset, uint phdr_size, uint i)
        {
            byte[] phdr = new byte[phdr_size];

            br.BaseStream.Seek(phdr_offset + phdr_size * i, SeekOrigin.Begin);
            br.Read(phdr, 0, phdr.Length);
            ELFLocation elfLocation = new ELFLocation();
            elfLocation.OffsetFile = byteToUInt(phdr, 0x0C);
            elfLocation.Offset = byteToUInt(phdr, 0x14);
            elfLocation.Size = byteToUInt(phdr, 0x24);
            Elf.Add(elfLocation);
            return 0;
        }

        public static ushort byteToUShort(byte[] b, int offset)
        {
            ushort a = (ushort)(b[offset] << 8);
            a |= (ushort)b[offset + 1];
            return a;
        }

        public static List LoadElf(string FileName)
        {
            List Elf = new List();
            BinaryReader br = new BinaryReader(File.OpenRead(FileName));

            byte[] elfMagic = new byte[4];
            br.Read(elfMagic, 0, 4);
            if (elfMagic[0] != 0x7F ||
                    elfMagic[1] != 0x45 ||
                    elfMagic[2] != 0x4C ||
                    elfMagic[3] != 0x46)
            {
                Console.WriteLine("Elf Magic Wrong (" + FileName + ")");
                br.Close();
                return Elf;
            }
            br.BaseStream.Seek(0, SeekOrigin.Begin);
            byte[] eHDR = new byte[0x40];
            br.Read(eHDR, 0, eHDR.Length);
            uint phdr_offset = byteToUInt(eHDR, 0x24);
            ushort n_phdrs = byteToUShort(eHDR, 0x38);
            ushort phdr_size = byteToUShort(eHDR, 0x36);
            for (ushort i = 0; i < n_phdrs; i++)
            {
                int error = LoadElfPHDR(br, Elf, phdr_offset, phdr_size, i);
                if (error == 1)
                    Console.WriteLine("Didn't Load phdr " + i + " of File " + FileName);
            }

            br.Close();
            return Elf;
        }

        public static List LoadPatchFile(string FileName)
        {
            List patches = new List();
            StreamReader sr = new StreamReader(File.OpenRead(FileName));

            string input;
            while(!string.IsNullOrEmpty(input = sr.ReadLine()))
            {
                string[] vals = input.Split(new char[] { ' ' });
                if (vals.Length != 3 || vals[0] != "00002000")
                {
                    Console.WriteLine("This is not an ELF Patch!");
                    patches.Clear();
                    return patches;
                }
                Patch p = new Patch();

                try
                {
                    p.Offset = uint.Parse(vals[1], System.Globalization.NumberStyles.AllowHexSpecifier);
                    p.PatchValue = uint.Parse(vals[2], System.Globalization.NumberStyles.AllowHexSpecifier);
                    patches.Add(p);
                }
                catch (Exception)
                {
                    Console.WriteLine("Patch file wrong!");
                    patches.Clear();
                    return patches;
                }
            }
            return patches;
        }

        static void Main(string[] args)
        {
            if (!File.Exists("EBOOT.ELF"))
            {
                Console.WriteLine("Couldn't find EBOOT.ELF");
                Console.ReadLine();
                return;
            }
            if (!File.Exists("PATCH.TXT"))
            {
                Console.WriteLine("Couldn't find PATCH.TXT");
                Console.ReadLine();
                return;
            }
            if (File.Exists("EBOOT.KDSBest.ELF"))
                File.Delete("EBOOT.KDSBest.ELF");
            List locations = LoadElf("EBOOT.ELF");
            List patches = LoadPatchFile("PATCH.TXT");
            for(int i = 0; i < patches.Count; i++)
            {
                ELFLocation? locationForPatch = null;
                Patch p = patches[i];
                for (int ii = 0; ii < locations.Count; ii++)
                {
                    if (p.Offset >= locations[ii].Offset && p.Offset < locations[ii].Offset + locations[ii].Size)
                    {
                        locationForPatch = locations[ii];
                        break;
                    }
                }

                if (locationForPatch == null)
                {
                    Console.WriteLine("Patch is not for this ELF!");
                    Console.ReadLine();
                    return;
                }
                else
                {
                    p.Offset = p.Offset - locationForPatch.Value.Offset + locationForPatch.Value.OffsetFile;
                    patches[i] = p;
                }
            }

            Console.WriteLine("Patching ELF...");
            File.Copy("EBOOT.ELF", "EBOOT.KDSBest.ELF");
            BinaryWriter bw = new BinaryWriter(File.OpenWrite("EBOOT.KDSBest.ELF"));
            foreach (Patch p in patches)
            {
                bw.Seek((int) p.Offset, SeekOrigin.Begin);
                bw.Write(uintToByte(p.PatchValue));
            }
            bw.Close();
            Console.WriteLine("DONE!");
            Console.ReadLine();
        }
    }
}
