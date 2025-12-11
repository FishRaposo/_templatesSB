/// Purchase Service - IAP and Premium status management
/// 
/// Handles in-app purchases for mobile and license validation for desktop.
/// 
/// CONFIDENTIAL - INTERNAL USE ONLY
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:in_app_purchase/in_app_purchase.dart';

import '../../core/errors/app_errors.dart';
import '../../core/logger/logger_service.dart';
import '../../core/result/result.dart';
import '../storage/storage_service.dart';

/// Purchase state
class PurchaseState {
  
  const PurchaseState({
    this.isPremium = false,
    this.isLoading = false,
    this.errorMessage,
  });
  final bool isPremium;
  final bool isLoading;
  final String? errorMessage;
  
  PurchaseState copyWith({
    bool? isPremium,
    bool? isLoading,
    String? errorMessage,
  }) {
    return PurchaseState(
      isPremium: isPremium ?? this.isPremium,
      isLoading: isLoading ?? this.isLoading,
      errorMessage: errorMessage,
    );
  }
}

/// Purchase service for handling IAP and license validation
class PurchaseService extends StateNotifier<PurchaseState> {
  
  PurchaseService({InAppPurchase? iap}) 
      : _iap = iap ?? InAppPurchase.instance,
        super(const PurchaseState());
  final InAppPurchase _iap;
  
  /// Product ID for premium upgrade
  static const String premiumProductId = 'premium_remove_ads';
  static const String _licenseModulusBase64 = 'w+F+2E7hII6Kvfbb3tcQIyinCeNvD2SdZDHFPv+XgI4jjx/WkOn/Sr/a+o8TGWEC/GYV/87awi9ULkvqUNcH0S9hwQrMi6Grj2z5GcBAUBCzYNqLcbbCtENLXr1wJsj97+Ak7h6r1UBTU4252YTUmR0cAnQ6z6ecte+a3faNfgPBWY9QwVhJE9WPhAzTQrFUEh5cs7WbEjGR0CPJFc+1EsC8SqNnNYXEfFhqqcdnLHwUnpspJ/xZDCsMI5J+JrAwoiLvg23phDo/na/fLuuFHyInR5d/5Z6m7W+ms891DkHoKHfW8DAaD2jDdhvO4hmXoKcIX/W4FZ/h4aX2VIQ5AQ==';
  static const String _licenseExponentBase64 = 'AQAB';
  static final BigInt _licenseModulus = _decodeBigIntFromBase64(_licenseModulusBase64);
  static final BigInt _licenseExponent = _decodeBigIntFromBase64(_licenseExponentBase64);
  
  /// Initializes the purchase service
  Future<void> initialize() async {
    // Check for existing purchase
    await _checkExistingPurchase();
    
    // Listen for purchase updates
    _iap.purchaseStream.listen(_handlePurchaseUpdate);
  }
  
  /// Checks for existing purchase token
  Future<void> _checkExistingPurchase() async {
    try {
      final token = await StorageService.getPurchaseToken();
      if (token != null) {
        state = state.copyWith(isPremium: true);
        logger.info('Existing purchase found');
      }
    } catch (e) {
      logger.error('Error checking existing purchase', {'error': e.toString()});
    }
  }
  
  /// Handles purchase stream updates
  void _handlePurchaseUpdate(List<PurchaseDetails> purchases) {
    for (final purchase in purchases) {
      if (purchase.status == PurchaseStatus.purchased ||
          purchase.status == PurchaseStatus.restored) {
        _handleSuccessfulPurchase(purchase);
      } else if (purchase.status == PurchaseStatus.error) {
        _handlePurchaseError(purchase);
      }
      
      // Complete pending purchases
      if (purchase.pendingCompletePurchase) {
        _iap.completePurchase(purchase);
      }
    }
  }
  
  /// Handles successful purchase
  Future<void> _handleSuccessfulPurchase(PurchaseDetails purchase) async {
    if (purchase.productID == premiumProductId) {
      // Save purchase token
      final token = purchase.purchaseID ?? DateTime.now().toIso8601String();
      await StorageService.savePurchaseToken(token);
      
      state = state.copyWith(isPremium: true, isLoading: false);
      logger.info('Premium purchased successfully');
    }
  }
  
  /// Handles purchase error
  void _handlePurchaseError(PurchaseDetails purchase) {
    state = state.copyWith(
      isLoading: false,
      errorMessage: purchase.error?.message ?? 'Purchase failed',
    );
    logger.error('Purchase error', {'error': purchase.error?.message});
  }
  
  /// Initiates premium purchase
  Future<Result<void, PurchaseError>> purchasePremium() async {
    state = state.copyWith(isLoading: true);
    
    try {
      // Check if IAP is available
      final available = await _iap.isAvailable();
      if (!available) {
        state = state.copyWith(isLoading: false);
        return const Result.failure(PurchaseErrorBillingUnavailable());
      }
      
      // Get product details
      final response = await _iap.queryProductDetails({premiumProductId});
      if (response.notFoundIDs.contains(premiumProductId)) {
        state = state.copyWith(isLoading: false);
        return const Result.failure(PurchaseErrorProductNotFound());
      }
      
      final product = response.productDetails.first;
      
      // Initiate purchase
      final purchaseParam = PurchaseParam(productDetails: product);
      await _iap.buyNonConsumable(purchaseParam: purchaseParam);
      
      return const Result.success(null);
    } catch (e) {
      state = state.copyWith(isLoading: false);
      logger.error('Purchase initiation failed', {'error': e.toString()});
      return Result.failure(PurchaseErrorUnknown(e.toString()));
    }
  }
  
  /// Restores previous purchases
  Future<Result<void, PurchaseError>> restorePurchases() async {
    state = state.copyWith(isLoading: true);
    
    try {
      await _iap.restorePurchases();
      
      // Wait a bit for the purchase stream to process
      await Future.delayed(const Duration(seconds: 2));
      
      if (!state.isPremium) {
        state = state.copyWith(isLoading: false);
        return const Result.failure(PurchaseErrorNoPurchaseFound());
      }
      
      state = state.copyWith(isLoading: false);
      return const Result.success(null);
    } catch (e) {
      state = state.copyWith(isLoading: false);
      logger.error('Restore purchases failed', {'error': e.toString()});
      return Result.failure(PurchaseErrorUnknown(e.toString()));
    }
  }
  
  /// Checks if running on desktop (for license validation)
  static bool get isDesktop => 
      Platform.isWindows || Platform.isMacOS || Platform.isLinux;
  
  /// Validates desktop license
  Future<Result<bool, LicenseError>> validateDesktopLicense() async {
    if (!isDesktop) {
      return const Result.success(true); // Not desktop, skip
    }
    
    try {
      final licenseKey = await StorageService.getLicenseKey();
      if (licenseKey == null) {
        return const Result.failure(LicenseErrorNotFound());
      }
      
      // Validate license format and signature
      final isValid = _validateLicenseKey(licenseKey);
      if (!isValid) {
        return const Result.failure(LicenseErrorInvalid());
      }
      
      state = state.copyWith(isPremium: true);
      return const Result.success(true);
    } catch (e) {
      logger.error('License validation failed', {'error': e.toString()});
      return const Result.failure(LicenseErrorInvalid());
    }
  }
  
  /// Validates license key format and signature
  bool _validateLicenseKey(String licenseKey) {
    // License format: BASE64(email:timestamp:signature)
    try {
      final decoded = utf8.decode(base64.decode(licenseKey));
      final parts = decoded.split(':');
      if (parts.length != 3) return false;
      
      final email = parts[0].trim();
      final timestamp = parts[1].trim();
      final signaturePart = parts[2].trim();
      if (email.isEmpty || timestamp.isEmpty || signaturePart.isEmpty) return false;
      
      final payload = Uint8List.fromList(utf8.encode('$email:$timestamp'));
      final signature = base64.decode(signaturePart);
      return _verifyRsaSignature(payload, signature);
    } catch (e) {
      return false;
    }
  }
  
  bool _verifyRsaSignature(Uint8List data, Uint8List signatureBytes) {
    if (_licenseModulus == BigInt.zero || _licenseExponent == BigInt.zero) {
      return false;
    }
    
    final signature = _bigIntFromBytes(signatureBytes);
    if (signature <= BigInt.zero || signature >= _licenseModulus) {
      return false;
    }
    
    final decrypted = signature.modPow(_licenseExponent, _licenseModulus);
    final keyBytesLength = (_licenseModulus.bitLength + 7) >> 3;
    final em = _bigIntToBytes(decrypted, keyBytesLength);
    
    final hash = sha256.convert(data).bytes;
    const digestInfoPrefix = <int>[
      0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    ];
    final expectedDigest = Uint8List(digestInfoPrefix.length + hash.length)
      ..setRange(0, digestInfoPrefix.length, digestInfoPrefix)
      ..setRange(digestInfoPrefix.length, digestInfoPrefix.length + hash.length, hash);
    
    if (em.length < expectedDigest.length + 11) return false;
    if (em[0] != 0x00 || em[1] != 0x01) return false;
    
    var paddingIndex = 2;
    while (paddingIndex < em.length && em[paddingIndex] == 0xff) {
      paddingIndex++;
    }
    
    if (paddingIndex - 2 < 8) return false; // PKCS#1 requires at least 8 padding bytes
    if (paddingIndex >= em.length || em[paddingIndex] != 0x00) return false;
    
    final digestStart = em.length - expectedDigest.length;
    if (digestStart != paddingIndex + 1) return false;
    
    for (var i = 0; i < expectedDigest.length; i++) {
      if (em[digestStart + i] != expectedDigest[i]) {
        return false;
      }
    }
    
    return true;
  }
  
  static BigInt _decodeBigIntFromBase64(String value) {
    final bytes = base64.decode(value);
    return _bigIntFromBytes(Uint8List.fromList(bytes));
  }
  
  static BigInt _bigIntFromBytes(Uint8List bytes) {
    var result = BigInt.zero;
    for (final byte in bytes) {
      result = (result << 8) | BigInt.from(byte);
    }
    return result;
  }
  
  static Uint8List _bigIntToBytes(BigInt number, int length) {
    var temp = number;
    final result = Uint8List(length);
    for (var i = length - 1; i >= 0; i--) {
      result[i] = (temp & BigInt.from(0xff)).toInt();
      temp = temp >> 8;
    }
    return result;
  }
  
  /// Activates desktop license
  Future<Result<void, LicenseError>> activateLicense(String licenseKey) async {
    if (!_validateLicenseKey(licenseKey)) {
      return const Result.failure(LicenseErrorInvalid());
    }
    
    await StorageService.saveLicenseKey(licenseKey);
    state = state.copyWith(isPremium: true);
    
    return const Result.success(null);
  }
}

/// Purchase service provider
final purchaseServiceProvider = StateNotifierProvider<PurchaseService, PurchaseState>((ref) {
  return PurchaseService();
});
