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
            var rdpWrap = new RDPWrap();
            await rdpWrap.Install();
        }
        
        [Fact]
        public async Task Should_Uninstall_RDPWrap()
        {
            var rdpWrap = new RDPWrap();
            await rdpWrap.Uninstall();
        }
    }
}