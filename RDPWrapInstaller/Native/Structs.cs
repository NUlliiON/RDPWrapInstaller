using System;
using System.Runtime.InteropServices;
using static RDPWrapInstaller.Native.Enums;
using WCHAR = System.Char;
using WORD = System.Int16;

namespace RDPWrapInstaller.Native
{
    internal class Structs
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct SYSTEM_INFO
        {
            public ushort wProcessorArchitecture;
            public ushort wReserved;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public UIntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public ushort wProcessorLevel;
            public ushort wProcessorRevision;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        public struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 42)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
        internal unsafe struct VS_VERSIONINFO
        {
            /// <summary>
            /// The length, in bytes, of the VS_VERSIONINFO structure
            /// </summary>
            [FieldOffset(0)]
            internal WORD wLength;

            /// <summary>
            /// The length, in bytes, of the Value member.
            /// </summary>
            [FieldOffset(2)]
            internal WORD wValueLength;

            /// <summary>
            /// The type of data in the version resource.
            /// This member is 1 if the version resource contains text data and 0 if the version resource contains binary data.
            /// </summary>
            [FieldOffset(4)]
            internal WORD wType;

            /// <summary>
            /// The Unicode string L"VS_VERSION_INFO".
            /// </summary>
            [FieldOffset(6)]
            internal fixed WCHAR szKey[15];

            /// <summary>
            /// Contains as many zero words as necessary to align the Value member on a 32-bit boundary.
            /// </summary>
            [FieldOffset(36)]
            internal WORD Padding1;

            /// <summary>
            /// Arbitrary data associated with this VS_VERSIONINFO structure.
            /// </summary>
            [FieldOffset(40)]
            internal VS_FIXEDFILEINFO Value;

            /// <summary>
            /// As many zero words as necessary to align the Children member on a 32-bit boundary.
            /// </summary>
            [FieldOffset(92)]
            internal WORD Padding2;

            /// <summary>
            /// An array of zero or one StringFileInfo structures,
            /// </summary>
            [FieldOffset(94)]
            internal WORD Children;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct VS_FIXEDFILEINFO
        {
            public UInt32 dwSignature;
            public UInt32 dwStrucVersion;
            public UInt32 dwFileVersionMS;
            public UInt32 dwFileVersionLS;
            public UInt32 dwProductVersionMS;
            public UInt32 dwProductVersionLS;
            public UInt32 dwFileFlagsMask;
            public UInt32 dwFileFlags;
            public UInt32 dwFileOS;
            public UInt32 dwFileType;
            public UInt32 dwFileSubtype;
            public UInt32 dwFileDateMS;
            public UInt32 dwFileDateLS;
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto, Pack = 0)] //Platform independent 32 & 64 bit - use Pack = 0 for both platforms
        public struct EXPLICIT_ACCESS
        {
            public uint grfAccessPermissions;
            public uint grfAccessMode;
            public uint grfInheritance;
            public TRUSTEE Trustee;
        }

        //Platform independent (32 & 64 bit) - use Pack = 0 for both platforms. IntPtr works as well.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto, Pack = 0)]
        public struct TRUSTEE : IDisposable
        {
            public IntPtr pMultipleTrustee;
            public MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
            public TRUSTEE_FORM TrusteeForm;
            public TRUSTEE_TYPE TrusteeType;
            private IntPtr ptstrName;

            void IDisposable.Dispose()
            {
                if (ptstrName != IntPtr.Zero) Marshal.Release(ptstrName);
            }

            public string Name { get { return Marshal.PtrToStringAuto(ptstrName); } }
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct SHARE_INFO_502
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string shi502_netname;
            public uint shi502_type;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string shi502_remark;
            public Int32 shi502_permissions;
            public Int32 shi502_max_uses;
            public Int32 shi502_current_uses;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string shi502_path;
            public IntPtr shi502_passwd;
            public Int32 shi502_reserved;
            public IntPtr shi502_security_descriptor;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ACL_SIZE_INFORMATION
        {
            public uint AceCount;
            public uint AclBytesInUse;
            public uint AclBytesFree;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ACE_HEADER
        {
            public byte AceType;
            public byte AceFlags;
            public short AceSize;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ACCESS_ALLOWED_ACE
        {
            public ACE_HEADER Header;
            public int Mask;
            public int SidStart;
        }
    }
}
