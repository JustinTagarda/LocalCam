using LocalCam.Models;
using LocalCam.Services;
using Xunit;

namespace LocalCam.Tests {
    public sealed class PremiumAddOnStoreConfigurationTests {
        [Fact]
        public void RecognizedPremiumAddOnStoreIds_ContainsLegacyAndActiveIds() {
            Assert.Contains(
                PremiumAddOnStoreConfiguration.LegacyPremiumAddOnStoreId,
                PremiumAddOnStoreConfiguration.RecognizedPremiumAddOnStoreIds);
            Assert.Contains(
                PremiumAddOnStoreConfiguration.ActivePremiumAddOnStoreId,
                PremiumAddOnStoreConfiguration.RecognizedPremiumAddOnStoreIds);
        }

        [Fact]
        public void ActivePremiumAddOnStoreId_IsNewPurchaseTarget() {
            Assert.Equal("9P18G2P91QV6", PremiumAddOnStoreConfiguration.ActivePremiumAddOnStoreId);
            Assert.NotEqual(
                PremiumAddOnStoreConfiguration.LegacyPremiumAddOnStoreId,
                PremiumAddOnStoreConfiguration.ActivePremiumAddOnStoreId);
        }

        [Theory]
        [InlineData("9P9KCJ3NFZFT")]
        [InlineData("9p9kcj3nfzft")]
        [InlineData(" 9P18G2P91QV6 ")]
        public void EntitlementService_RecognizesConfiguredPremiumIds(string storeId) {
            var service = CreateEntitlementService();

            Assert.True(service.IsRecognizedPremiumStoreId(storeId));
        }

        [Fact]
        public void EntitlementService_DoesNotRecognizeUnknownId() {
            var service = CreateEntitlementService();

            Assert.False(service.IsRecognizedPremiumStoreId("UNKNOWN"));
        }

        private static PremiumEntitlementService CreateEntitlementService() {
            return new PremiumEntitlementService(
                new StoreContextProvider(),
                new LocalCamSettings(),
                () => IntPtr.Zero,
                PremiumAddOnStoreConfiguration.RecognizedPremiumAddOnStoreIds);
        }
    }
}
