using System;
using System.Threading.Tasks;
using Xunit;

namespace RDPWrapInstaller.Tests
{
    public class UnitTest1
    {
        [Fact]
        public async Task Should_Install_RDPWrap()
        {
            await RDPWrap.Install();
        }
        
        [Fact]
        public void Should_Uninstall_RDPWrap()
        {
            RDPWrap.Uninstall();
        }
    }
}