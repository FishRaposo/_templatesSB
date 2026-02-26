/// Ad Banner Slot - Non-intrusive banner ad widget
/// 
/// CONFIDENTIAL - INTERNAL USE ONLY
library;

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:google_mobile_ads/google_mobile_ads.dart';

import '../core/config/app_config.dart';

/// Ad banner widget that displays non-intrusively
class AdBannerSlot extends StatefulWidget {
  const AdBannerSlot({super.key});

  @override
  State<AdBannerSlot> createState() => _AdBannerSlotState();
}

class _AdBannerSlotState extends State<AdBannerSlot> {
  BannerAd? _bannerAd;
  bool _isLoaded = false;

  @override
  void initState() {
    super.initState();
    _loadAd();
  }

  @override
  void dispose() {
    _bannerAd?.dispose();
    super.dispose();
  }

  void _loadAd() {
    // Only load ads on mobile platforms
    if (!Platform.isAndroid && !Platform.isIOS) return;

    final adUnitId = _getAdUnitId();
    if (adUnitId.isEmpty) return;

    _bannerAd = BannerAd(
      adUnitId: adUnitId,
      size: AdSize.banner,
      request: const AdRequest(),
      listener: BannerAdListener(
        onAdLoaded: (ad) {
          setState(() => _isLoaded = true);
        },
        onAdFailedToLoad: (ad, error) {
          ad.dispose();
          debugPrint('Ad failed to load: ${error.message}');
        },
      ),
    )..load();
  }

  String _getAdUnitId() {
    final config = ConfigService.instance;
    if (Platform.isAndroid) {
      return config.adUnitIds['banner_android'] ?? '';
    } else if (Platform.isIOS) {
      return config.adUnitIds['banner_ios'] ?? '';
    }
    return '';
  }

  @override
  Widget build(BuildContext context) {
    if (!_isLoaded || _bannerAd == null) {
      return const SizedBox.shrink();
    }

    return Container(
      alignment: Alignment.center,
      width: _bannerAd!.size.width.toDouble(),
      height: _bannerAd!.size.height.toDouble(),
      child: AdWidget(ad: _bannerAd!),
    );
  }
}
