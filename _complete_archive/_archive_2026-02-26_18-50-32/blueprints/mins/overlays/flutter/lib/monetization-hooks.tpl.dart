// -----------------------------------------------------------------------------
// FILE: monetization-hooks.tpl.dart
// PURPOSE: MINS blueprint monetization hooks with integrated payment and ad functionality
// USAGE: Import and adapt for monetization in MINS blueprint Flutter projects
// AUTHOR: {{AUTHOR}}
// VERSION: {{VERSION}}
// SINCE: {{VERSION}}
// -----------------------------------------------------------------------------

```dart
// MINS Blueprint Monetization Hooks
// Integrated payment and ad functionality

import 'package:flutter/material.dart';
import 'package:in_app_purchase/in_app_purchase.dart';
import 'package:google_mobile_ads/google_mobile_ads.dart';

// MINS monetization service
class MinsMonetizationService {
  static final MinsMonetizationService _instance = MinsMonetizationService._internal();
  factory MinsMonetizationService() => _instance;
  MinsMonetizationService._internal();

  bool _isPremium = false;
  bool _adsInitialized = false;
  BannerAd? _bannerAd;
  final InAppPurchase _inAppPurchase = InAppPurchase.instance;

  bool get isPremium => _isPremium;
  bool get adsInitialized => _adsInitialized;
  BannerAd? get bannerAd => _bannerAd;

  // Initialize monetization
  Future<void> initialize() async {
    await _initializeAds();
    await _initializePurchases();
    await _loadPremiumStatus();
  }

  // Initialize ads (mobile only)
  Future<void> _initializeAds() async {
    try {
      await MobileAds.instance.initialize();
      _adsInitialized = true;
      _createBannerAd();
    } catch (e) {
      print('Failed to initialize ads: $e');
    }
  }

  // Create banner ad
  void _createBannerAd() {
    _bannerAd = BannerAd(
      adUnitId: '{{AD_UNIT_ID}}',
      size: AdSize.banner,
      request: const AdRequest(),
      listener: BannerAdListener(
        onAdLoaded: (ad) => print('Banner ad loaded'),
        onAdFailedToLoad: (ad, error) {
          print('Banner ad failed to load: $error');
          ad.dispose();
        },
      ),
    );
    _bannerAd?.load();
  }

  // Initialize in-app purchases
  Future<void> _initializePurchases() async {
    if (await _inAppPurchase.isAvailable()) {
      // Listen to purchase updates
      _inAppPurchase.purchaseStream.listen(_listenToPurchaseUpdated);
    }
  }

  // Load premium status from local storage
  Future<void> _loadPremiumStatus() async {
    // TODO: Load from secure storage
    _isPremium = false; // Default to false
  }

  // Purchase premium
  Future<bool> purchasePremium() async {
    try {
      final ProductDetailsResponse response = await _inAppPurchase.queryProductDetails({'{{PREMIUM_PRODUCT_ID}}'});
      
      if (response.productDetails.isNotEmpty) {
        final PurchaseParam purchaseParam = PurchaseParam(productDetails: response.productDetails.first);
        final bool purchaseResult = await _inAppPurchase.buyNonConsumable(purchaseParam: purchaseParam);
        return purchaseResult;
      }
    } catch (e) {
      print('Purchase failed: $e');
    }
    return false;
  }

  // Restore purchases
  Future<bool> restorePurchases() async {
    try {
      await _inAppPurchase.restorePurchases();
      return true;
    } catch (e) {
      print('Restore failed: $e');
      return false;
    }
  }

  // Listen to purchase updates
  void _listenToPurchaseUpdated(List<PurchaseDetails> purchaseDetailsList) {
    for (final PurchaseDetails purchaseDetails in purchaseDetailsList) {
      _handlePurchase(purchaseDetails);
    }
  }

  // Handle successful purchase
  void _handlePurchase(PurchaseDetails purchaseDetails) {
    if (purchaseDetails.productID == '{{PREMIUM_PRODUCT_ID}}' && purchaseDetails.status == PurchaseStatus.purchased) {
      _isPremium = true;
      _savePremiumStatus();
      _hideAds();
    }
  }

  // Save premium status
  Future<void> _savePremiumStatus() async {
    // TODO: Save to secure storage
  }

  // Hide ads when premium is purchased
  void _hideAds() {
    _bannerAd?.dispose();
    _bannerAd = null;
  }

  // Premium feature gate
  bool isFeatureUnlocked(String featureId) {
    if (_isPremium) return true;
    
    // Define which features are available in free tier
    final freeFeatures = ['core_feature', 'basic_analytics'];
    return freeFeatures.contains(featureId);
  }

  // Show premium upgrade dialog
  void showPremiumUpgradeDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: const Text('Upgrade to Premium'),
          content: const Text(
            'Get access to premium features for a one-time payment of $9.99.\n\n'
            'Premium features include:\n'
            '• {{PREMIUM_FEATURE_1}}\n'
            '• {{PREMIUM_FEATURE_2}}\n'
            '• {{PREMIUM_FEATURE_3}}\n'
            '• Remove all ads',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Maybe Later'),
            ),
            ElevatedButton(
              onPressed: () {
                Navigator.of(context).pop();
                purchasePremium();
              },
              child: const Text('Buy Premium - $9.99'),
            ),
          ],
        );
      },
    );
  }
}

// Premium feature wrapper widget
class PremiumFeature extends StatelessWidget {
  final Widget child;
  final String featureId;
  final String? upgradeMessage;

  const PremiumFeature({
    super.key,
    required this.child,
    required this.featureId,
    this.upgradeMessage,
  });

  @override
  Widget build(BuildContext context) {
    final monetization = MinsMonetizationService();
    
    if (monetization.isFeatureUnlocked(featureId)) {
      return child;
    } else {
      return GestureDetector(
        onTap: () => monetization.showPremiumUpgradeDialog(context),
        child: Stack(
          children: [
            child,
            Container(
              decoration: BoxDecoration(
                color: Colors.black.withOpacity(0.7),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Center(
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(Icons.lock, color: Colors.white, size: 32),
                    SizedBox(height: 8),
                    Text(
                      'Premium Feature',
                      style: TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    Text(
                      'Tap to unlock',
                      style: TextStyle(
                        color: Colors.white70,
                        fontSize: 12,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      );
    }
  }
}

// Ad banner widget (shown only for free users)
class MinsAdBanner extends StatelessWidget {
  const MinsAdBanner({super.key});

  @override
  Widget build(BuildContext context) {
    final monetization = MinsMonetizationService();
    
    if (monetization.isPremium || !monetization.adsInitialized || monetization.bannerAd == null) {
      return const SizedBox.shrink();
    }

    return Container(
      width: monetization.bannerAd!.size.width.toDouble(),
      height: monetization.bannerAd!.size.height.toDouble(),
      child: AdWidget(ad: monetization.bannerAd!),
    );
  }
}

// License validation for desktop builds
class MinsLicenseValidator {
  static Future<bool> validateLicense(String licenseKey) async {
    // TODO: Implement offline license validation for desktop builds
    // This should check against a hardcoded public key or local validation
    return true; // Placeholder
  }

  static Future<void> activateLicense(String licenseKey) async {
    // TODO: Save activated license to secure storage
  }
}
```
