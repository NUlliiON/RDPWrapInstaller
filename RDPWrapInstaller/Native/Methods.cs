using System;
using System.Runtime.InteropServices;
using static RDPWrapInstaller.Native.Enums;
using static RDPWrapInstaller.Native.Structs;

namespace RDPWrapInstaller.Native
{
    internal class Methods
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);

        // Use this signature if you want the previous state information returned
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
           [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges,
           ref TOKEN_PRIVILEGES NewState,
           UInt32 BufferLengthInBytes,
           ref TOKEN_PRIVILEGES PreviousState,
           out UInt32 ReturnLengthInBytes);


        [DllImport("version.dll")]
        public static extern int GetFileVersionInfoSize(string fileName, ref int ptr);

        [DllImport("version.dll")] //for desktop application
        public static extern bool GetFileVersionInfo(string filename, int handle, int len, IntPtr buffer);

        [DllImport("version.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool VerQueryValue(IntPtr pBlock, string lpSubBlock, ref IntPtr lplpBuffer, ref int puLen);


        [DllImport("kernel32.dll")]
        internal static extern void GetNativeSystemInfo(ref SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll")]
        internal static extern void GetSystemInfo(ref SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Wow64DisableWow64FsRedirection(ref IntPtr ptr);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Wow64RevertWow64FsRedirection(IntPtr ptr);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern uint SetNamedSecurityInfoW(String pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern bool ConvertStringSidToSid(String StringSid, ref IntPtr Sid);

        //[DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        //public static extern uint SetNamedSecurityInfo(
        //    string pObjectName,
        //    SE_OBJECT_TYPE ObjectType,
        //    SECURITY_INFORMATION SecurityInfo,
        //    IntPtr psidOwner,
        //    IntPtr psidGroup,
        //    IntPtr pDacl,
        //    IntPtr pSacl);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int SetEntriesInAcl(
            int cCountOfExplicitEntries,
            ref EXPLICIT_ACCESS pListOfExplicitEntries,
            IntPtr OldAcl,
            out IntPtr NewAcl);



        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int NetShareGetInfo(
        [MarshalAs(UnmanagedType.LPWStr)] string serverName,
        [MarshalAs(UnmanagedType.LPWStr)] string netName,
        Int32 level,
        out IntPtr bufPtr);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetSecurityDescriptorDacl(
            IntPtr pSecurityDescriptor,
            [MarshalAs(UnmanagedType.Bool)] out bool bDaclPresent,
            ref IntPtr pDacl,
            [MarshalAs(UnmanagedType.Bool)] out bool bDaclDefaulted
            );

        //[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        //[return: MarshalAs(UnmanagedType.Bool)]
        //static extern bool GetAclInformation(
        //    IntPtr pAcl,
        //    ref ACL_SIZE_INFORMATION pAclInformation,
        //    uint nAclInformationLength,
        //    ACL_INFORMATION_CLASS dwAclInformationClass
        // );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int GetAce(
            IntPtr aclPtr,
            int aceIndex,
            out IntPtr acePtr
         );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int GetLengthSid(
            IntPtr pSID
         );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool ConvertSidToStringSid(
            [MarshalAs(UnmanagedType.LPArray)] byte[] pSID,
            out IntPtr ptrSid
         );

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int NetApiBufferFree(
            IntPtr buffer
         );
    }
}
