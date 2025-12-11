# React Native Integration Testing Template
# Comprehensive integration testing patterns for React Native projects
# Device APIs, Firebase, navigation, gestures, and third-party services

"""
React Native Integration Test Patterns
Device features, Firebase integration, navigation flows, and gesture handling
Including camera, location, contacts, and push notifications
"""

import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react-native';
import { Provider } from 'react-redux';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import * as ImagePicker from 'react-native-image-picker';
import * as Permissions from 'react-native-permissions';
import Geolocation from '@react-native-community/geolocation';
import Contacts from 'react-native-contacts';
import CameraRoll from '@react-native-community/cameraroll';

// ====================
// DEVICE API INTEGRATION
// ====================

describe('Device API Integration Tests', () => {
  
  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Mock permissions
    jest.spyOn(Permissions, 'check').mockResolvedValue(Permissions.RESULTS.GRANTED);
    jest.spyOn(Permissions, 'request').mockResolvedValue(Permissions.RESULTS.GRANTED);
  });
  
  test('camera integration with permissions', async () => {
    // Mock ImagePicker
    jest.spyOn(ImagePicker, 'launchCamera').mockResolvedValue({
      assets: [{
        uri: 'file:///test-image.jpg',
        type: 'image/jpeg',
        fileName: 'test-image.jpg',
        width: 1920,
        height: 1080
      }]
    });
    
    const { getByText, getByTestId } = render(<CameraScreen />);
    
    const cameraButton = getByText('Take Photo');
    fireEvent.press(cameraButton);
    
    await waitFor(() => {
      expect(getByTestId('captured-image')).toBeTruthy();
      expect(ImagePicker.launchCamera).toHaveBeenCalledWith({
        mediaType: 'photo',
        quality: 0.8,
        includeBase64: false
      });
    });
  });
  
  test('photo gallery integration', async () => {
    // Mock CameraRoll
    jest.spyOn(CameraRoll, 'getPhotos').mockResolvedValue({
      edges: [
        {
          node: {
            image: { uri: 'photo1.jpg', width: 1920, height: 1080 },
            timestamp: 1234567890,
            type: 'image'
          }
        },
        {
          node: {
            image: { uri: 'photo2.jpg', width: 1920, height: 1080 },
            timestamp: 1234567891,
            type: 'image'
          }
        }
      ],
      page_info: {
        has_next_page: false,
        start_cursor: null,
        end_cursor: null
      }
    });
    
    const { getByText, getAllByTestId } = render(<PhotoGallery />);
    
    const loadButton = getByText('Load Photos');
    fireEvent.press(loadButton);
    
    await waitFor(() => {
      const photos = getAllByTestId('gallery-photo');
      expect(photos).toHaveLength(2);
      expect(CameraRoll.getPhotos).toHaveBeenCalledWith({
        first: 20,
        assetType: 'Photos'
      });
    });
  });
  
  test('location services integration', async () => {
    // Mock Geolocation
    jest.spyOn(Geolocation, 'getCurrentPosition').mockImplementation((success) => {
      success({
        coords: {
          latitude: 37.7749,
          longitude: -122.4194,
          altitude: 10,
          accuracy: 10,
          altitudeAccuracy: 5,
          heading: 0,
          speed: 0
        },
        timestamp: Date.now()
      });
    });
    
    const { getByText } = render(<LocationTracker />);
    
    const getLocationButton = getByText('Get Current Location');
    fireEvent.press(getLocationButton);
    
    await waitFor(() => {
      expect(getByText('Latitude: 37.7749')).toBeTruthy();
      expect(getByText('Longitude: -122.4194')).toBeTruthy();
      expect(Geolocation.getCurrentPosition).toHaveBeenCalled();
    });
  });
  
  test('contacts integration', async () => {
    // Mock Contacts
    jest.spyOn(Contacts, 'getAll').mockResolvedValue([
      {
        recordID: '1',
        displayName: 'John Doe',
        givenName: 'John',
        familyName: 'Doe',
        phoneNumbers: [{ label: 'mobile', number: '+1234567890' }],
        emailAddresses: [{ label: 'work', email: 'john@example.com' }]
      },
      {
        recordID: '2',
        displayName: 'Jane Smith',
        givenName: 'Jane',
        familyName: 'Smith',
        phoneNumbers: [{ label: 'mobile', number: '+1987654321' }],
        emailAddresses: [{ label: 'work', email: 'jane@example.com' }]
      }
    ]);
    
    const { getByText, getAllByTestId } = render(<ContactList />);
    
    const loadContactsButton = getByText('Load Contacts');
    fireEvent.press(loadContactsButton);
    
    await waitFor(() => {
      const contacts = getAllByTestId('contact-item');
      expect(contacts).toHaveLength(2);
      expect(getByText('John Doe')).toBeTruthy();
      expect(getByText('Jane Smith')).toBeTruthy();
      expect(Contacts.getAll).toHaveBeenCalled();
    });
  });
  
  test('device sensors integration', async () => {
    // Mock accelerometer
    const mockAccelerometer = {
      subscribe: jest.fn((callback) => {
        callback({ x: 0.1, y: 0.2, z: 9.8 });
        return { unsubscribe: jest.fn() };
      })
    };
    
    jest.mock('react-native-sensors', () => ({
      accelerometer: mockAccelerometer
    }));
    
    const { getByText } = render(<SensorData />);
    
    const startButton = getByText('Start Sensors');
    fireEvent.press(startButton);
    
    await waitFor(() => {
      expect(getByText('X: 0.1')).toBeTruthy();
      expect(getByText('Y: 0.2')).toBeTruthy();
      expect(getByText('Z: 9.8')).toBeTruthy();
    });
  });
});

// ====================
// FIREBASE INTEGRATION
// ====================

describe('Firebase Integration Tests', () => {
  
  beforeEach(() => {
    // Mock Firebase modules
    jest.mock('@react-native-firebase/auth', () => ({
      auth: jest.fn(() => ({
        currentUser: null,
        signInWithEmailAndPassword: jest.fn().mockResolvedValue({
          user: { uid: 'test-uid', email: 'test@example.com' }
        }),
        createUserWithEmailAndPassword: jest.fn().mockResolvedValue({
          user: { uid: 'new-uid', email: 'new@example.com' }
        }),
        signOut: jest.fn().mockResolvedValue(undefined),
        onAuthStateChanged: jest.fn((callback) => {
          callback({ uid: 'test-uid', email: 'test@example.com' });
          return () => {}; // unsubscribe function
        })
      }))
    }));
    
    jest.mock('@react-native-firebase/firestore', () => ({
      firestore: jest.fn(() => ({
        collection: jest.fn(() => ({
          doc: jest.fn(() => ({
            get: jest.fn().mockResolvedValue({
              exists: true,
              data: () => ({ name: 'Test User', email: 'test@example.com' })
            }),
            set: jest.fn().mockResolvedValue(undefined),
            update: jest.fn().mockResolvedValue(undefined),
            delete: jest.fn().mockResolvedValue(undefined)
          })),
          get: jest.fn().mockResolvedValue({
            docs: [
              { id: '1', data: () => ({ name: 'Item 1' }) },
              { id: '2', data: () => ({ name: 'Item 2' }) }
            ]
          }),
          add: jest.fn().mockResolvedValue({ id: 'new-doc-id' }),
          where: jest.fn(() => ({
            get: jest.fn().mockResolvedValue({
              docs: [{ id: '1', data: () => ({ name: 'Filtered Item' }) }]
            })
          })),
          orderBy: jest.fn(() => ({
            get: jest.fn().mockResolvedValue({
              docs: [
                { id: '1', data: () => ({ name: 'Item A' }) },
                { id: '2', data: () => ({ name: 'Item B' }) }
              ]
            })
          }))
        })),
        batch: jest.fn(() => ({
          set: jest.fn(),
          update: jest.fn(),
          delete: jest.fn(),
          commit: jest.fn().mockResolvedValue(undefined)
        }))
      }))
    }));
    
    jest.mock('@react-native-firebase/messaging', () => ({
      messaging: jest.fn(() => ({
        requestPermission: jest.fn().mockResolvedValue(true),
        getToken: jest.fn().mockResolvedValue('test-device-token'),
        onMessage: jest.fn((callback) => {
          callback({
            notification: { title: 'Test', body: 'Test message' },
            data: { key: 'value' }
          });
          return () => {}; // unsubscribe function
        }),
        onNotificationOpenedApp: jest.fn((callback) => {
          callback({
            notification: { title: 'Opened', body: 'App opened from notification' }
          });
          return () => {}; // unsubscribe function
        }),
        getInitialNotification: jest.fn().mockResolvedValue(null)
      }))
    }));
  });
  
  test('user authentication flow', async () => {
    const { getByPlaceholderText, getByText } = render(<LoginScreen />);
    
    const emailInput = getByPlaceholderText('Email');
    const passwordInput = getByPlaceholderText('Password');
    const loginButton = getByText('Login');
    
    fireEvent.changeText(emailInput, 'test@example.com');
    fireEvent.changeText(passwordInput, 'password123');
    fireEvent.press(loginButton);
    
    await waitFor(() => {
      expect(getByText('Welcome, test@example.com')).toBeTruthy();
    });
  });
  
  test('firestore data operations', async () => {
    const { getByText, getAllByTestId } = render(<UserList />);
    
    const loadButton = getByText('Load Users');
    fireEvent.press(loadButton);
    
    await waitFor(() => {
      const users = getAllByTestId('user-item');
      expect(users).toHaveLength(2);
      expect(getByText('Test User')).toBeTruthy();
    });
  });
  
  test('push notification handling', async () => {
    const { getByText } = render(<NotificationHandler />);
    
    await waitFor(() => {
      expect(getByText('Test')).toBeTruthy();
      expect(getByText('Test message')).toBeTruthy();
    });
  });
  
  test('offline data persistence', async () => {
    // Mock offline persistence
    jest.mock('@react-native-firebase/firestore', () => ({
      firestore: jest.fn(() => ({
        enablePersistence: jest.fn().mockResolvedValue(undefined),
        collection: jest.fn(() => ({
          doc: jest.fn(() => ({
            get: jest.fn().mockResolvedValue({
              exists: true,
              data: () => ({ name: 'Cached User' }),
              metadata: { fromCache: true }
            })
          }))
        }))
      }))
    }));
    
    const { getByText } = render(<OfflineDataHandler />);
    
    const loadButton = getByText('Load Cached Data');
    fireEvent.press(loadButton);
    
    await waitFor(() => {
      expect(getByText('Cached User')).toBeTruthy();
    });
  });
});

// ====================
// NAVIGATION INTEGRATION
// ====================

describe('Navigation Integration Tests', () => {
  
  const Stack = createStackNavigator();
  
  test('complex navigation flows', async () => {
    const { getByText } = render(
      <NavigationContainer>
        <Stack.Navigator>
          <Stack.Screen name="Home" component={HomeScreen} />
          <Stack.Screen name="Products" component={ProductsScreen} />
          <Stack.Screen name="ProductDetail" component={ProductDetailScreen} />
          <Stack.Screen name="Cart" component={CartScreen} />
          <Stack.Screen name="Checkout" component={CheckoutScreen} />
        </Stack.Navigator>
      </NavigationContainer>
    );
    
    // Navigate through multiple screens
    fireEvent.press(getByText('Browse Products'));
    await waitFor(() => expect(getByText('Products')).toBeTruthy());
    
    fireEvent.press(getByText('Product 1'));
    await waitFor(() => expect(getByText('Product Detail')).toBeTruthy());
    
    fireEvent.press(getByText('Add to Cart'));
    await waitFor(() => expect(getByText('Added to Cart')).toBeTruthy());
    
    fireEvent.press(getByText('View Cart'));
    await waitFor(() => expect(getByText('Shopping Cart')).toBeTruthy());
    
    fireEvent.press(getByText('Checkout'));
    await waitFor(() => expect(getByText('Checkout')).toBeTruthy());
  });
  
  test('deep linking navigation', async () => {
    const linking = {
      prefixes: ['myapp://'],
      config: {
        screens: {
          Product: 'product/:id',
          Profile: 'user/:userId'
        }
      }
    };
    
    const { getByText } = render(
      <NavigationContainer linking={linking}>
        <Stack.Navigator>
          <Stack.Screen name="Product" component={ProductScreen} />
          <Stack.Screen name="Profile" component={ProfileScreen} />
        </Stack.Navigator>
      </NavigationContainer>
    );
    
    // Simulate deep link
    const deepLink = 'myapp://product/123';
    Linking.openURL(deepLink);
    
    await waitFor(() => {
      expect(getByText('Product ID: 123')).toBeTruthy();
    });
  });
  
  test('navigation with authentication guards', async () => {
    const mockAuthContext = {
      isAuthenticated: false,
      login: jest.fn()
    });
    
    const ProtectedRoute = ({ children }) => {
      return mockAuthContext.isAuthenticated ? children : <LoginScreen />;
    };
    
    const { getByText } = render(
      <NavigationContainer>
        <Stack.Navigator>
          <Stack.Screen name="Public" component={PublicScreen} />
          <Stack.Screen name="Protected">
            {() => (
              <ProtectedRoute>
                <ProtectedScreen />
              </ProtectedRoute>
            )}
          </Stack.Screen>
        </Stack.Navigator>
      </NavigationContainer>
    );
    
    // Try to access protected route
    fireEvent.press(getByText('Go to Protected Area'));
    
    await waitFor(() => {
      expect(getByText('Please Login')).toBeTruthy();
    });
    
    // Mock login
    mockAuthContext.isAuthenticated = true;
    
    fireEvent.press(getByText('Login'));
    await waitFor(() => {
      expect(getByText('Protected Content')).toBeTruthy();
    });
  });
});

// ====================
// GESTURE INTEGRATION
// ====================

describe('Gesture Integration Tests', () => {
  
  test('PanResponder gesture handling', async () => {
    const onSwipe = jest.fn();
    const { getByTestId } = render(
      <SwipeableCard onSwipe={onSwipe}>
        <Text>Swipeable Content</Text>
      </SwipeableCard>
    );
    
    const card = getByTestId('swipeable-card');
    
    // Simulate swipe gesture
    fireEvent(card, 'responderGrant', { nativeEvent: { pageX: 100, pageY: 100 } });
    fireEvent(card, 'responderMove', { nativeEvent: { pageX: 200, pageY: 100 } });
    fireEvent(card, 'responderRelease', { nativeEvent: { pageX: 200, pageY: 100 } });
    
    await waitFor(() => {
      expect(onSwipe).toHaveBeenCalledWith('right');
    });
  });
  
  test('React Native Gesture Handler integration', async () => {
    const { getByTestId } = render(
      <GestureHandlerRootView>
        <PinchableImage>
          <Image source={{ uri: 'test.jpg' }} testID="pinchable-image" />
        </PinchableImage>
      </GestureHandlerRootView>
    );
    
    const image = getByTestId('pinchable-image');
    
    // Simulate pinch gesture
    fireEvent(image, 'gestureHandler', {
      nativeEvent: { scale: 2.0, velocity: 1.5 }
    });
    
    await waitFor(() => {
      expect(image.props.style.transform[0].scale).toBe(2.0);
    });
  });
  
  test('multi-touch gesture recognition', async () => {
    const onMultiTouch = jest.fn();
    const { getByTestId } = render(
      <MultiTouchComponent onMultiTouch={onMultiTouch}>
        <Text>Multi-touch Area</Text>
      </MultiTouchComponent>
    );
    
    const touchArea = getByTestId('multi-touch-area');
    
    // Simulate multi-touch
    fireEvent(touchArea, 'touchStart', {
      nativeEvent: {
        touches: [
          { identifier: 1, pageX: 100, pageY: 100 },
          { identifier: 2, pageX: 200, pageY: 200 }
        ]
      }
    });
    
    fireEvent(touchArea, 'touchEnd', {
      nativeEvent: {
        touches: []
      }
    });
    
    await waitFor(() => {
      expect(onMultiTouch).toHaveBeenCalledWith(2);
    });
  });
});

// ====================
// THIRD-PARTY SERVICE INTEGRATION
// ====================

describe('Third-Party Service Integration Tests', () => {
  
  test('payment gateway integration', async () => {
    // Mock Stripe
    jest.mock('@stripe/stripe-react-native', () => ({
      StripeProvider: ({ children }) => children,
      CardField: jest.fn(() => null),
      useStripe: () => ({
        confirmPayment: jest.fn().mockResolvedValue({
          paymentIntent: { status: 'succeeded' }
        }),
        createPaymentMethod: jest.fn().mockResolvedValue({
          paymentMethod: { id: 'pm_test123' }
        })
      })
    }));
    
    const { getByText, getByPlaceholderText } = render(<PaymentScreen />);
    
    const cardNumberInput = getByPlaceholderText('Card Number');
    const expiryInput = getByPlaceholderText('MM/YY');
    const cvcInput = getByPlaceholderText('CVC');
    
    fireEvent.changeText(cardNumberInput, '4242424242424242');
    fireEvent.changeText(expiryInput, '12/25');
    fireEvent.changeText(cvcInput, '123');
    
    const payButton = getByText('Pay Now');
    fireEvent.press(payButton);
    
    await waitFor(() => {
      expect(getByText('Payment Successful')).toBeTruthy();
    });
  });
  
  test('analytics service integration', async () => {
    // Mock analytics
    const mockAnalytics = {
      logEvent: jest.fn(),
      setUserId: jest.fn(),
      setUserProperties: jest.fn(),
      logScreenView: jest.fn()
    };
    
    jest.mock('@react-native-firebase/analytics', () => ({
      analytics: () => mockAnalytics
    }));
    
    const { getByText } = render(<AnalyticsScreen />);
    
    const trackButton = getByText('Track Event');
    fireEvent.press(trackButton);
    
    await waitFor(() => {
      expect(mockAnalytics.logEvent).toHaveBeenCalledWith('button_click', {
        button_name: 'Track Event'
      });
    });
  });
  
  test('social media sharing integration', async () => {
    // Mock sharing
    jest.mock('react-native-share', () => ({
      default: jest.fn().mockResolvedValue({ success: true, message: 'Shared' })
    }));
    
    const { getByText } = render(<ShareScreen />);
    
    const shareButton = getByText('Share Content');
    fireEvent.press(shareButton);
    
    await waitFor(() => {
      expect(getByText('Shared successfully')).toBeTruthy();
    });
  });
});

// ====================
// NETWORK INTEGRATION
// ====================

describe('Network Integration Tests', () => {
  
  test('offline/online state handling', async () => {
    // Mock NetInfo
    jest.mock('@react-native-community/netinfo', () => ({
      addEventListener: jest.fn((callback) => {
        callback({ isConnected: false, type: 'none' });
        return () => {}; // unsubscribe
      }),
      fetch: jest.fn().mockResolvedValue({ isConnected: true, type: 'wifi' })
    }));
    
    const { getByText } = render(<NetworkAwareComponent />);
    
    await waitFor(() => {
      expect(getByText('Offline Mode')).toBeTruthy();
    });
  });
  
  test('API retry mechanism', async () => {
    let attemptCount = 0;
    
    global.fetch = jest.fn().mockImplementation(() => {
      attemptCount++;
      if (attemptCount < 3) {
        return Promise.reject(new Error('Network error'));
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ data: 'success' })
      });
    });
    
    const { getByText } = render(<ApiRetryComponent />);
    
    const fetchButton = getByText('Fetch Data');
    fireEvent.press(fetchButton);
    
    await waitFor(() => {
      expect(getByText('Data loaded successfully')).toBeTruthy();
      expect(global.fetch).toHaveBeenCalledTimes(3);
    }, { timeout: 10000 });
  });
});

// ====================
// MOCK CONFIGURATION
// ====================

// Global mock setup for integration tests
jest.mock('react-native-permissions', () => ({
  check: jest.fn().mockResolvedValue('granted'),
  request: jest.fn().mockResolvedValue('granted'),
  RESULTS: {
    UNAVAILABLE: 'unavailable',
    DENIED: 'denied',
    LIMITED: 'limited',
    GRANTED: 'granted',
    BLOCKED: 'blocked'
  },
  PERMISSIONS: {
    IOS: {
      CAMERA: 'ios.permission.CAMERA',
      PHOTO_LIBRARY: 'ios.permission.PHOTO_LIBRARY',
      LOCATION_WHEN_IN_USE: 'ios.permission.LOCATION_WHEN_IN_USE',
      CONTACTS: 'ios.permission.CONTACTS'
    },
    ANDROID: {
      CAMERA: 'android.permission.CAMERA',
      READ_EXTERNAL_STORAGE: 'android.permission.READ_EXTERNAL_STORAGE',
      ACCESS_FINE_LOCATION: 'android.permission.ACCESS_FINE_LOCATION',
      READ_CONTACTS: 'android.permission.READ_CONTACTS'
    }
  }
}));

jest.mock('@react-native-community/geolocation', () => ({
  getCurrentPosition: jest.fn((success, error, options) => {
    success({
      coords: {
        latitude: 37.7749,
        longitude: -122.4194,
        altitude: 10,
        accuracy: 10,
        altitudeAccuracy: 5,
        heading: 0,
        speed: 0
      },
      timestamp: Date.now()
    });
  }),
  watchPosition: jest.fn(),
  clearWatch: jest.fn(),
  stopObserving: jest.fn()
}));

jest.mock('react-native-contacts', () => ({
  getAll: jest.fn().mockResolvedValue([
    {
      recordID: '1',
      displayName: 'John Doe',
      givenName: 'John',
      familyName: 'Doe',
      phoneNumbers: [{ label: 'mobile', number: '+1234567890' }],
      emailAddresses: [{ label: 'work', email: 'john@example.com' }]
    }
  ]),
  addContact: jest.fn().mockResolvedValue(undefined),
  updateContact: jest.fn().mockResolvedValue(undefined),
  deleteContact: jest.fn().mockResolvedValue(undefined),
  requestPermission: jest.fn().mockResolvedValue(true),
  checkPermission: jest.fn().mockResolvedValue(true)
}));

jest.mock('react-native-image-picker', () => ({
  launchCamera: jest.fn().mockResolvedValue({
    assets: [{
      uri: 'file:///test-image.jpg',
      type: 'image/jpeg',
      fileName: 'test-image.jpg',
      width: 1920,
      height: 1080
    }]
  }),
  launchImageLibrary: jest.fn().mockResolvedValue({
    assets: [{
      uri: 'file:///library-image.jpg',
      type: 'image/jpeg',
      fileName: 'library-image.jpg',
      width: 1920,
      height: 1080
    }]
  })
}));

jest.mock('@react-native-community/cameraroll', () => ({
  getPhotos: jest.fn().mockResolvedValue({
    edges: [
      {
        node: {
          image: { uri: 'photo1.jpg', width: 1920, height: 1080 },
          timestamp: 1234567890,
          type: 'image'
        }
      }
    ],
    page_info: {
      has_next_page: false,
      start_cursor: null,
      end_cursor: null
    }
  }),
  saveToCameraRoll: jest.fn().mockResolvedValue(undefined),
  deletePhotos: jest.fn().mockResolvedValue(undefined)
}));

jest.mock('react-native-sensors', () => ({
  accelerometer: {
    subscribe: jest.fn((callback) => {
      callback({ x: 0.1, y: 0.2, z: 9.8 });
      return { unsubscribe: jest.fn() };
    })
  },
  gyroscope: {
    subscribe: jest.fn((callback) => {
      callback({ x: 0.01, y: 0.02, z: 0.03 });
      return { unsubscribe: jest.fn() };
    })
  },
  magnetometer: {
    subscribe: jest.fn((callback) => {
      callback({ x: 10, y: 20, z: 30 });
      return { unsubscribe: jest.fn() };
    })
  }
}));

jest.mock('@react-native-community/netinfo', () => ({
  addEventListener: jest.fn((callback) => {
    callback({ isConnected: true, type: 'wifi', details: { strength: 100 } });
    return () => {}; // unsubscribe
  }),
  fetch: jest.fn().mockResolvedValue({ isConnected: true, type: 'wifi' }),
  getConnectionInfo: jest.fn().mockResolvedValue({ type: 'wifi' })
}));

jest.mock('react-native-share', () => ({
  default: jest.fn().mockResolvedValue({ success: true, message: 'Shared' }),
  Social: {
    FACEBOOK: 'facebook',
    TWITTER: 'twitter',
    WHATSAPP: 'whatsapp'
  }
}));

// Setup for React Navigation testing
jest.mock('@react-navigation/native', () => ({
  ...jest.requireActual('@react-navigation/native'),
  useNavigation: () => ({
    navigate: jest.fn(),
    goBack: jest.fn(),
    addListener: jest.fn(() => () => {}),
    removeListener: jest.fn(),
    isFocused: jest.fn(() => true),
    getState: jest.fn(() => ({ routes: [] }))
  }),
  useRoute: () => ({
    params: { id: '123' },
    name: 'TestScreen',
    key: 'test-key'
  }),
  useFocusEffect: jest.fn((callback) => callback()),
  useIsFocused: jest.fn(() => true),
  useScrollToTop: jest.fn()
}));

// Setup for gesture handler testing
jest.mock('react-native-gesture-handler', () => ({
  GestureHandlerRootView: ({ children }) => children,
  PanGestureHandler: ({ children }) => children,
  PinchGestureHandler: ({ children }) => children,
  RotationGestureHandler: ({ children }) => children,
  TapGestureHandler: ({ children }) => children,
  State: {
    BEGAN: 0,
    FAILED: 1,
    CANCELLED: 2,
    ACTIVE: 4,
    END: 5
  }
}));

// Custom integration test utilities
class IntegrationTestUtils {
  static async waitForAsyncOperations(timeout = 5000) {
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 100));
    });
  }
  
  static mockPermissions(granted = true) {
    const result = granted ? 'granted' : 'denied';
    jest.spyOn(Permissions, 'check').mockResolvedValue(result);
    jest.spyOn(Permissions, 'request').mockResolvedValue(result);
  }
  
  static mockNetwork(connected = true) {
    jest.mock('@react-native-community/netinfo', () => ({
      addEventListener: jest.fn((callback) => {
        callback({ isConnected: connected, type: connected ? 'wifi' : 'none' });
        return () => {};
      }),
      fetch: jest.fn().mockResolvedValue({ isConnected: connected, type: connected ? 'wifi' : 'none' })
    }));
  }
  
  static cleanup() {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  }
}

// Export utilities
export { IntegrationTestUtils };