using System;
using Xunit;

namespace RDPWrapInstaller.Tests
{
    public class UnitTest1
    {
        [Fact]
        public void Should_Install_RDPWrap()
        {
            RDPWrap.Install();
        }
        
        [Fact]
        public void Should_Uninstall_RDPWrap()
        {
            RDPWrap.Uninstall();
        }
    }
}