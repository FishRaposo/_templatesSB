# React Native Unit Testing Template
# Comprehensive unit testing patterns for React Native projects with mobile-specific considerations

"""
React Native Unit Test Patterns
Complete component, hook, Redux, and navigation testing with React Native Testing Library
Including mobile-specific patterns for gestures, platform differences, and native modules
"""

import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react-native';
import { renderHook } from '@testing-library/react-hooks';
import '@testing-library/jest-native/extend-expect';
import { Provider } from 'react-redux';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';

// ====================
// BASIC COMPONENT TESTS
// ====================

describe('Basic Component Tests', () => {
  
  test('renders component with props', () => {
    const { getByText, getByTestId } = render(
      <UserCard name="John Doe" email="john@example.com" />
    );
    
    expect(getByText('John Doe')).toBeTruthy();
    expect(getByText('john@example.com')).toBeTruthy();
    expect(getByTestId('user-card')).toBeTruthy();
  });
  
  test('component handles touch events', async () => {
    const handlePress = jest.fn();
    const { getByText } = render(
      <TouchableOpacity onPress={handlePress}>
        <Text>Press Me</Text>
      </TouchableOpacity>
    );
    
    const button = getByText('Press Me');
    fireEvent.press(button);
    
    expect(handlePress).toHaveBeenCalledTimes(1);
  });
  
  test('component with conditional rendering', () => {
    const { rerender, queryByTestId } = render(
      <LoadingSpinner isLoading={true} />
    );
    
    expect(queryByTestId('activity-indicator')).toBeTruthy();
    
    rerender(<LoadingSpinner isLoading={false} />);
    
    expect(queryByTestId('activity-indicator')).toBeFalsy();
  });
  
  test('form component with controlled inputs', async () => {
    const handleSubmit = jest.fn();
    const { getByPlaceholderText, getByText } = render(
      <LoginForm onSubmit={handleSubmit} />
    );
    
    const emailInput = getByPlaceholderText('Enter email');
    const passwordInput = getByPlaceholderText('Enter password');
    const submitButton = getByText('Login');
    
    fireEvent.changeText(emailInput, 'test@example.com');
    fireEvent.changeText(passwordInput, 'password123');
    fireEvent.press(submitButton);
    
    await waitFor(() => {
      expect(handleSubmit).toHaveBeenCalledWith({
        email: 'test@example.com',
        password: 'password123'
      });
    });
  });
  
  test('component with platform-specific rendering', () => {
    const { getByTestId } = render(<PlatformSpecificComponent />);
    
    // iOS-specific test
    Platform.OS = 'ios';
    expect(getByTestId('ios-component')).toBeTruthy();
    
    // Android-specific test  
    Platform.OS = 'android';
    const { getByTestId: getAndroidByTestId } = render(<PlatformSpecificComponent />);
    expect(getAndroidByTestId('android-component')).toBeTruthy();
  });
});

// ====================
// HOOK TESTING
// ====================

describe('Custom Hook Tests', () => {
  
  test('useAuth hook manages authentication state', () => {
    const { result } = renderHook(() => useAuth());
    
    expect(result.current.isAuthenticated).toBe(false);
    expect(result.current.user).toBeNull();
    
    act(() => {
      result.current.login('test@example.com', 'password');
    });
    
    expect(result.current.isAuthenticated).toBe(true);
    expect(result.current.user).toBeTruthy();
  });
  
  test('useApi hook handles API calls', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      json: () => Promise.resolve({ data: 'test data' }),
      ok: true,
      status: 200
    });
    
    const { result, waitForNextUpdate } = renderHook(() => useApi());
    
    act(() => {
      result.current.fetchData('/api/test');
    });
    
    await waitForNextUpdate();
    
    expect(result.current.data).toEqual({ data: 'test data' });
    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBeNull();
  });
  
  test('useLocalStorage hook persists data', () => {
    const { result } = renderHook(() => useLocalStorage('test-key', 'initial'));
    
    expect(result.current[0]).toBe('initial');
    
    act(() => {
      result.current[1]('updated value');
    });
    
    expect(result.current[0]).toBe('updated value');
    expect(localStorage.getItem('test-key')).toBe('"updated value"');
  });
  
  test('useNetwork hook detects connection changes', () => {
    const { result } = renderHook(() => useNetwork());
    
    expect(result.current.isConnected).toBe(true);
    
    act(() => {
      // Simulate offline event
      NetInfo.mockImplementationOnce(() => ({
        isConnected: false
      }));
    });
    
    expect(result.current.isConnected).toBe(false);
  });
});

// ====================
// REDUX INTEGRATION TESTS
// ====================

describe('Redux Integration Tests', () => {
  let store;
  
  beforeEach(() => {
    store = configureStore({
      reducer: {
        auth: authReducer,
        user: userReducer,
        products: productsReducer
      }
    });
  });
  
  test('connected component receives Redux state', () => {
    const { getByText } = render(
      <Provider store={store}>
        <UserProfile />
      </Provider>
    );
    
    expect(getByText('John Doe')).toBeTruthy();
  });
  
  test('component dispatches actions correctly', async () => {
    const { getByText } = render(
      <Provider store={store}>
        <LoginButton />
      </Provider>
    );
    
    const loginButton = getByText('Login');
    fireEvent.press(loginButton);
    
    await waitFor(() => {
      const actions = store.getActions();
      expect(actions).toContainEqual({
        type: 'auth/login',
        payload: { email: 'user@example.com' }
      });
    });
  });
  
  test('Redux thunk async actions', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      json: () => Promise.resolve({ id: 1, name: 'Product' }),
      ok: true
    });
    
    const { getByText } = render(
      <Provider store={store}>
        <ProductList />
      </Provider>
    );
    
    const loadButton = getByText('Load Products');
    fireEvent.press(loadButton);
    
    await waitFor(() => {
      const state = store.getState();
      expect(state.products.items).toHaveLength(1);
      expect(state.products.loading).toBe(false);
    });
  });
});

// ====================
// NAVIGATION TESTS
// ====================

describe('Navigation Tests', () => {
  const Stack = createStackNavigator();
  
  test('navigates between screens', () => {
    const { getByText } = render(
      <NavigationContainer>
        <Stack.Navigator>
          <Stack.Screen name="Home" component={HomeScreen} />
          <Stack.Screen name="Details" component={DetailsScreen} />
        </Stack.Navigator>
      </NavigationContainer>
    );
    
    const navigateButton = getByText('Go to Details');
    fireEvent.press(navigateButton);
    
    expect(getByText('Details Screen')).toBeTruthy();
  });
  
  test('passes parameters between screens', () => {
    const { getByText } = render(
      <NavigationContainer>
        <Stack.Navigator>
          <Stack.Screen name="Home" component={HomeScreen} />
          <Stack.Screen name="Profile" component={ProfileScreen} />
        </Stack.Navigator>
      </NavigationContainer>
    );
    
    const profileButton = getByText('View Profile');
    fireEvent.press(profileButton);
    
    expect(getByText('John Doe')).toBeTruthy();
    expect(getByText('john@example.com')).toBeTruthy();
  });
  
  test('handles navigation header options', () => {
    const { getByText } = render(
      <NavigationContainer>
        <Stack.Navigator>
          <Stack.Screen 
            name="Home" 
            component={HomeScreen}
            options={{ title: 'My App' }}
          />
        </Stack.Navigator>
      </NavigationContainer>
    );
    
    expect(getByText('My App')).toBeTruthy();
  });
});

// ====================
// GESTURE TESTING
// ====================

describe('Gesture Testing', () => {
  
  test('handles swipe gestures', () => {
    const onSwipeLeft = jest.fn();
    const { getByTestId } = render(
      <SwipeableCard onSwipeLeft={onSwipeLeft}>
        <Text>Swipeable Content</Text>
      </SwipeableCard>
    );
    
    const card = getByTestId('swipeable-card');
    fireEvent(card, 'swipeLeft');
    
    expect(onSwipeLeft).toHaveBeenCalledTimes(1);
  });
  
  test('handles pinch gestures', () => {
    const onPinch = jest.fn();
    const { getByTestId } = render(
      <ZoomableImage onPinch={onPinch}>
        <Image source={{ uri: 'test.jpg' }} />
      </ZoomableImage>
    );
    
    const image = getByTestId('zoomable-image');
    fireEvent(image, 'pinch', { scale: 2.0 });
    
    expect(onPinch).toHaveBeenCalledWith({ scale: 2.0 });
  });
  
  test('handles long press', () => {
    const onLongPress = jest.fn();
    const { getByText } = render(
      <TouchableOpacity onLongPress={onLongPress}>
        <Text>Long Press Me</Text>
      </TouchableOpacity>
    );
    
    const element = getByText('Long Press Me');
    fireEvent(element, 'longPress');
    
    expect(onLongPress).toHaveBeenCalledTimes(1);
  });
});

// ====================
// NATIVE MODULE MOCKING
// ====================

describe('Native Module Mocking', () => {
  
  beforeEach(() => {
    // Mock CameraRoll
    jest.mock('@react-native-community/cameraroll', () => ({
      getPhotos: jest.fn().mockResolvedValue({
        edges: [
          {
            node: {
              image: { uri: 'photo1.jpg' },
              timestamp: 1234567890
            }
          }
        ]
      })
    }));
    
    // Mock Geolocation
    global.navigator.geolocation = {
      getCurrentPosition: jest.fn((success) => {
        success({
          coords: {
            latitude: 37.7749,
            longitude: -122.4194,
            accuracy: 10
          }
        });
      }),
      watchPosition: jest.fn()
    };
  });
  
  test('CameraRoll integration', async () => {
    const { getByText } = render(<PhotoGallery />);
    
    const loadButton = getByText('Load Photos');
    fireEvent.press(loadButton);
    
    await waitFor(() => {
      expect(getByText('photo1.jpg')).toBeTruthy();
    });
  });
  
  test('Geolocation services', async () => {
    const { getByText } = render(<LocationTracker />);
    
    const getLocationButton = getByText('Get Location');
    fireEvent.press(getLocationButton);
    
    await waitFor(() => {
      expect(getByText('37.7749, -122.4194')).toBeTruthy();
    });
  });
});

// ====================
// ANIMATION TESTING
// ====================

describe('Animation Testing', () => {
  
  beforeEach(() => {
    jest.useFakeTimers();
  });
  
  afterEach(() => {
    jest.useRealTimers();
  });
  
  test('fade in animation', () => {
    const { getByTestId } = render(<FadeInComponent />);
    
    const animatedView = getByTestId('animated-view');
    expect(animatedView.props.style.opacity).toBe(0);
    
    act(() => {
      jest.runAllTimers();
    });
    
    expect(animatedView.props.style.opacity).toBe(1);
  });
  
  test('spring animation', () => {
    const { getByTestId } = render(<SpringAnimation />);
    
    const animatedView = getByTestId('spring-view');
    const initialScale = animatedView.props.style.transform[0].scale;
    
    act(() => {
      jest.runAllTimers();
    });
    
    const finalScale = animatedView.props.style.transform[0].scale;
    expect(finalScale).toBeGreaterThan(initialScale);
  });
});

// ====================
// ACCESSIBILITY TESTING
// ====================

describe('Accessibility Testing', () => {
  
  test('screen reader compatibility', () => {
    const { getByLabelText } = render(
      <TouchableOpacity accessibilityLabel="Submit Form">
        <Text>Submit</Text>
      </TouchableOpacity>
    );
    
    expect(getByLabelText('Submit Form')).toBeTruthy();
  });
  
  test('accessibility roles', () => {
    const { getByRole } = render(
      <View>
        <Button accessibilityRole="button" title="Click Me" />
        <Text accessibilityRole="header">Header Text</Text>
      </View>
    );
    
    expect(getByRole('button')).toBeTruthy();
    expect(getByRole('header')).toBeTruthy();
  });
  
  test('accessibility hints', () => {
    const { getByLabelText } = render(
      <TouchableOpacity 
        accessibilityLabel="Delete Item"
        accessibilityHint="Deletes the selected item permanently"
      >
        <Text>Delete</Text>
      </TouchableOpacity>
    );
    
    const element = getByLabelText('Delete Item');
    expect(element.props.accessibilityHint).toBe('Deletes the selected item permanently');
  });
});

// ====================
// PERFORMANCE TESTING
// ====================

describe('Performance Testing', () => {
  
  test('component render performance', async () => {
    const startTime = performance.now();
    
    const { unmount } = render(<HeavyComponent />);
    
    const endTime = performance.now();
    const renderTime = endTime - startTime;
    
    expect(renderTime).toBeLessThan(100); // Should render in less than 100ms
    
    unmount();
  });
  
  test('list rendering performance', () => {
    const items = Array.from({ length: 1000 }, (_, i) => ({
      id: i,
      title: `Item ${i}`
    }));
    
    const startTime = performance.now();
    
    const { getAllByTestId } = render(<LargeList items={items} />);
    
    const endTime = performance.now();
    const renderTime = endTime - startTime;
    
    expect(renderTime).toBeLessThan(200); // Should render in less than 200ms
    expect(getAllByTestId('list-item')).toHaveLength(1000);
  });
  
  test('memory leak prevention', () => {
    const { unmount } = render(<MemoryIntensiveComponent />);
    
    // Component should clean up on unmount
    unmount();
    
    // Verify cleanup (implementation specific)
    expect(cleanupSpy).toHaveBeenCalled();
  });
});

// ====================
// ERROR BOUNDARY TESTING
// ====================

describe('Error Boundary Testing', () => {
  
  test('catches and handles component errors', () => {
    const ThrowError = () => {
      throw new Error('Test error');
    };
    
    const { getByText } = render(
      <ErrorBoundary>
        <ThrowError />
      </ErrorBoundary>
    );
    
    expect(getByText('Something went wrong')).toBeTruthy();
  });
  
  test('displays fallback UI on error', () => {
    const BrokenComponent = () => {
      throw new Error('Component broken');
    };
    
    const { getByText, getByTestId } = render(
      <ErrorBoundary fallback={<ErrorFallback />}>
        <BrokenComponent />
      </ErrorBoundary>
    );
    
    expect(getByText('Error occurred')).toBeTruthy();
    expect(getByTestId('error-boundary')).toBeTruthy();
  });
});

// ====================
// MOCK UTILITIES
// ====================

// Mock React Navigation
jest.mock('@react-navigation/native', () => ({
  ...jest.requireActual('@react-navigation/native'),
  useNavigation: () => ({
    navigate: jest.fn(),
    goBack: jest.fn(),
    addListener: jest.fn()
  }),
  useRoute: () => ({
    params: { id: '123' }
  })
}));

// Mock Native Modules
jest.mock('react-native-device-info', () => ({
  getVersion: () => '1.0.0',
  getBuildNumber: () => '100',
  getModel: () => 'iPhone 12'
}));

// Mock AsyncStorage
jest.mock('@react-native-async-storage/async-storage', () => ({
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn()
}));

// Mock Firebase
jest.mock('@react-native-firebase/auth', () => ({
  auth: () => ({
    currentUser: { uid: 'test-uid', email: 'test@example.com' },
    signInWithEmailAndPassword: jest.fn(),
    createUserWithEmailAndPassword: jest.fn(),
    signOut: jest.fn()
  })
}));

// ====================
// TEST CONFIGURATION
// ====================

// Setup Jest configuration for React Native
const jestConfig = {
  preset: 'react-native',
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  transformIgnorePatterns: [
    'node_modules/(?!(react-native|@react-native|@react-navigation)/)'
  ],
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1'
  },
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    '!src/**/*.test.{js,jsx,ts,tsx}',
    '!src/index.js'
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  }
};

// Custom matchers for React Native
expect.extend({
  toBeVisible(element) {
    if (element && element.props && element.props.style) {
      const style = Array.isArray(element.props.style) 
        ? element.props.style 
        : [element.props.style];
      const isVisible = !style.some(s => s && s.opacity === 0);
      
      return {
        message: () => `expected element to be visible`,
        pass: isVisible
      };
    }
    
    return {
      message: () => `expected element to have style properties`,
      pass: false
    };
  }
});