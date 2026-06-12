using LocalCam.Services;
using Xunit;

namespace LocalCam.Tests;

public sealed class PremiumEntitlementRulesTests {
    [Fact]
    public void MatchesPremiumLicense_ReturnsTrue_ForExactSkuStoreId() {
        var matched = PremiumEntitlementRules.MatchesPremiumLicense(
            "9P9KCJ3NFZFT",
            null,
            "9P9KCJ3NFZFT",
            null,
            isActive: true);

        Assert.True(matched);
    }

    [Fact]
    public void MatchesPremiumLicense_ReturnsTrue_ForSkuStoreIdPrefix() {
        var matched = PremiumEntitlementRules.MatchesPremiumLicense(
            "9P9KCJ3NFZFT",
            null,
            "9P9KCJ3NFZFT.premium",
            null,
            isActive: true);

        Assert.True(matched);
    }

    [Fact]
    public void MatchesPremiumLicense_ReturnsTrue_ForConfiguredOfferToken() {
        var matched = PremiumEntitlementRules.MatchesPremiumLicense(
            "9P9KCJ3NFZFT",
            "localcam_premium_lifetime",
            null,
            "localcam_premium_lifetime",
            isActive: true);

        Assert.True(matched);
    }

    [Fact]
    public void MatchesPremiumLicense_ReturnsFalse_ForInactiveLicense() {
        var matched = PremiumEntitlementRules.MatchesPremiumLicense(
            "9P9KCJ3NFZFT",
            "localcam_premium_lifetime",
            "9P9KCJ3NFZFT.premium",
            "localcam_premium_lifetime",
            isActive: false);

        Assert.False(matched);
    }

    [Fact]
    public void MatchesPremiumLicense_ReturnsFalse_ForUnrelatedAddOn() {
        var matched = PremiumEntitlementRules.MatchesPremiumLicense(
            "9P9KCJ3NFZFT",
            null,
            "111111111111.basic",
            null,
            isActive: true);

        Assert.False(matched);
    }

    [Fact]
    public void MatchesPremiumCollectionProduct_ReturnsTrue_ForExactStoreId() {
        var matched = PremiumEntitlementRules.MatchesPremiumCollectionProduct(
            "9P9KCJ3NFZFT",
            "9P9KCJ3NFZFT",
            isInUserCollection: true);

        Assert.True(matched);
    }

    [Fact]
    public void MatchesPremiumCollectionProduct_ReturnsFalse_ForUnrelatedProduct() {
        var matched = PremiumEntitlementRules.MatchesPremiumCollectionProduct(
            "9P9KCJ3NFZFT",
            "111111111111",
            isInUserCollection: true);

        Assert.False(matched);
    }
}
