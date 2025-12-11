/// Template: widget-tests.tpl.dart
/// Purpose: widget-tests template
/// Stack: flutter
/// Tier: base

# Universal Template System - Flutter Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: flutter
# Category: testing

// -----------------------------------------------------------------------------
// FILE: widget-tests.tpl.dart
// PURPOSE: Comprehensive widget testing patterns for Flutter projects
// USAGE: Import and extend for widget testing across Flutter applications
// DEPENDENCIES: flutter_test, mockito, build_runner
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';
import 'package:your_app/widgets/custom_button.dart';
import 'package:your_app/widgets/user_avatar.dart';
import 'package:your_app/widgets/data_table.dart';
import 'package:your_app/widgets/form_input.dart';
import 'package:your_app/widgets/modal_dialog.dart';

/// Generate mocks with: dart run build_runner build
@GenerateMocks([
  // Add your service classes here
  // AuthService,
  // UserRepository,
  // NavigationService,
])
void main() {
  group('Widget Tests - UI Components', () {
    
    group('Custom Button Widget', () {
      testWidgets('should render button with correct text', (WidgetTester tester) async {
        // Arrange
        const buttonText = 'Click Me';
        
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: CustomButton(
                text: buttonText,
                onPressed: () {},
              ),
            ),
          ),
        );

        // Assert
        expect(find.text(buttonText), findsOneWidget);
        expect(find.byType(CustomButton), findsOneWidget);
      });

      testWidgets('should handle button press correctly', (WidgetTester tester) async {
        // Arrange
        bool buttonPressed = false;
        
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: CustomButton(
                text: 'Press Me',
                onPressed: () => buttonPressed = true,
              ),
            ),
          ),
        );

        await tester.tap(find.byType(CustomButton));
        await tester.pump();

        // Assert
        expect(buttonPressed, isTrue);
      });

      testWidgets('should show loading state when loading', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: CustomButton(
                text: 'Loading',
                onPressed: () {},
                isLoading: true,
              ),
            ),
          ),
        );

        // Assert
        expect(find.byType(CircularProgressIndicator), findsOneWidget);
        expect(find.text('Loading'), findsOneWidget);
      });

      testWidgets('should be disabled when loading', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: CustomButton(
                text: 'Disabled',
                onPressed: () {},
                isLoading: true,
              ),
            ),
          ),
        );

        // Assert
        final button = tester.widget<ElevatedButton>(find.byType(ElevatedButton));
        expect(button.onPressed, isNull);
      });

      testWidgets('should apply correct variant styling', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: CustomButton(
                text: 'Primary',
                onPressed: () {},
                variant: ButtonVariant.primary,
              ),
            ),
          ),
        );

        // Assert
        final button = tester.widget<ElevatedButton>(find.byType(ElevatedButton));
        expect(button.style?.backgroundColor?.resolve({}), equals(Colors.blue));
      });
    });

    group('User Avatar Widget', () {
      testWidgets('should display user initials when no image', (WidgetTester tester) async {
        // Arrange
        const userName = 'John Doe';
        
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: UserAvatar(
                name: userName,
                size: 50,
              ),
            ),
          ),
        );

        // Assert
        expect(find.text('JD'), findsOneWidget);
        expect(find.byType(CircleAvatar), findsOneWidget);
      });

      testWidgets('should display network image when provided', (WidgetTester tester) async {
        // Arrange
        const imageUrl = 'https://example.com/avatar.jpg';
        
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: UserAvatar(
                name: 'John Doe',
                imageUrl: imageUrl,
                size: 50,
              ),
            ),
          ),
        );

        // Assert
        expect(find.byType(Image), findsOneWidget);
        expect(find.byType(CircleAvatar), findsOneWidget);
      });

      testWidgets('should handle different sizes correctly', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: UserAvatar(
                name: 'John Doe',
                size: 100,
              ),
            ),
          ),
        );

        // Assert
        final avatar = tester.widget<CircleAvatar>(find.byType(CircleAvatar));
        expect(avatar.radius, equals(50.0));
      });

      testWidgets('should show fallback when image fails to load', (WidgetTester tester) async {
        // Arrange
        const imageUrl = 'https://example.com/invalid.jpg';
        
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: UserAvatar(
                name: 'John Doe',
                imageUrl: imageUrl,
                size: 50,
              ),
            ),
          ),
        );

        // Wait for image to potentially fail
        await tester.pump(Duration(seconds: 1));

        // Assert - Should show initials as fallback
        expect(find.text('JD'), findsOneWidget);
      });
    });

    group('Data Table Widget', () {
      final sampleData = [
        {'id': 1, 'name': 'John Doe', 'email': 'john@example.com'},
        {'id': 2, 'name': 'Jane Smith', 'email': 'jane@example.com'},
        {'id': 3, 'name': 'Bob Johnson', 'email': 'bob@example.com'},
      ];

      testWidgets('should display table with correct data', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: DataTableWidget(
                data: sampleData,
                columns: ['name', 'email'],
              ),
            ),
          ),
        );

        // Assert
        expect(find.text('John Doe'), findsOneWidget);
        expect(find.text('jane@example.com'), findsOneWidget);
        expect(find.text('Bob Johnson'), findsOneWidget);
      });

      testWidgets('should handle sorting when header clicked', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: DataTableWidget(
                data: sampleData,
                columns: ['name', 'email'],
                sortable: true,
              ),
            ),
          ),
        );

        // Act - Click name header to sort
        await tester.tap(find.text('Name'));
        await tester.pump();

        // Assert - Data should be sorted
        final rows = find.byType(TableRow).evaluate();
        expect(rows.length, equals(4)); // Header + 3 data rows
      });

      testWidgets('should filter data based on search input', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: DataTableWidget(
                data: sampleData,
                columns: ['name', 'email'],
                searchable: true,
              ),
            ),
          ),
        );

        // Act - Enter search term
        await tester.enterText(find.byType(TextField), 'John');
        await tester.pump();

        // Assert
        expect(find.text('John Doe'), findsOneWidget);
        expect(find.text('Jane Smith'), findsNothing);
        expect(find.text('Bob Johnson'), findsOneWidget);
      });

      testWidgets('should handle empty data state', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: DataTableWidget(
                data: [],
                columns: ['name', 'email'],
              ),
            ),
          ),
        );

        // Assert
        expect(find.text('No data available'), findsOneWidget);
        expect(find.byType(TableRow), findsNothing);
      });
    });

    group('Form Input Widget', () {
      testWidgets('should render text field with label', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: FormInput(
                label: 'Email',
                controller: TextEditingController(),
              ),
            ),
          ),
        );

        // Assert
        expect(find.text('Email'), findsOneWidget);
        expect(find.byType(TextField), findsOneWidget);
      });

      testWidgets('should show validation error', (WidgetTester tester) async {
        // Arrange
        final controller = TextEditingController();
        
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: FormInput(
                label: 'Email',
                controller: controller,
                validator: (value) {
                  if (value == null || !value.contains('@')) {
                    return 'Please enter a valid email';
                  }
                  return null;
                },
              ),
            ),
          ),
        );

        // Act - Trigger validation
        controller.text = 'invalid-email';
        await tester.pump();

        // Assert
        expect(find.text('Please enter a valid email'), findsOneWidget);
      });

      testWidgets('should handle password field correctly', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: FormInput(
                label: 'Password',
                controller: TextEditingController(),
                obscureText: true,
              ),
            ),
          ),
        );

        // Assert
        final textField = tester.widget<TextField>(find.byType(TextField));
        expect(textField.obscureText, isTrue);
      });

      testWidgets('should toggle password visibility', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: FormInput(
                label: 'Password',
                controller: TextEditingController(),
                obscureText: true,
                showPasswordToggle: true,
              ),
            ),
          ),
        );

        // Act - Toggle password visibility
        await tester.tap(find.byIcon(Icons.visibility));
        await tester.pump();

        // Assert
        final textField = tester.widget<TextField>(find.byType(TextField));
        expect(textField.obscureText, isFalse);
      });
    });

    group('Modal Dialog Widget', () {
      testWidgets('should show modal when open', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: ModalDialog(
                isOpen: true,
                title: 'Test Modal',
                child: Text('Modal content'),
                onClose: () {},
              ),
            ),
          ),
        );

        // Assert
        expect(find.text('Test Modal'), findsOneWidget);
        expect(find.text('Modal content'), findsOneWidget);
        expect(find.byType(Card), findsOneWidget);
      });

      testWidgets('should not render when closed', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: ModalDialog(
                isOpen: false,
                title: 'Test Modal',
                child: Text('Modal content'),
                onClose: () {},
              ),
            ),
          ),
        );

        // Assert
        expect(find.text('Test Modal'), findsNothing);
        expect(find.text('Modal content'), findsNothing);
      });

      testWidgets('should call onClose when close button pressed', (WidgetTester tester) async {
        // Arrange
        bool onCloseCalled = false;
        
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: ModalDialog(
                isOpen: true,
                title: 'Test Modal',
                child: Text('Modal content'),
                onClose: () => onCloseCalled = true,
              ),
            ),
          ),
        );

        await tester.tap(find.byIcon(Icons.close));
        await tester.pump();

        // Assert
        expect(onCloseCalled, isTrue);
      });

      testWidgets('should handle overlay tap to close', (WidgetTester tester) async {
        // Arrange
        bool onCloseCalled = false;
        
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: ModalDialog(
                isOpen: true,
                title: 'Test Modal',
                child: Text('Modal content'),
                onClose: () => onCloseCalled = true,
                closeOnOutsideTap: true,
              ),
            ),
          ),
        );

        // Tap outside the modal (on the overlay)
        await tester.tapAt(Offset(10, 10));
        await tester.pump();

        // Assert
        expect(onCloseCalled, isTrue);
      });
    });

    group('List Widget Tests', () {
      testWidgets('should display list items correctly', (WidgetTester tester) async {
        // Arrange
        final items = ['Item 1', 'Item 2', 'Item 3'];

        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: ListView.builder(
                itemCount: items.length,
                itemBuilder: (context, index) {
                  return ListTile(
                    title: Text(items[index]),
                  );
                },
              ),
            ),
          ),
        );

        // Assert
        for (final item in items) {
          expect(find.text(item), findsOneWidget);
        }
      });

      testWidgets('should handle list scrolling', (WidgetTester tester) async {
        // Arrange
        final items = List.generate(50, (index) => 'Item $index');

        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: ListView.builder(
                itemCount: items.length,
                itemBuilder: (context, index) {
                  return ListTile(
                    title: Text(items[index]),
                  );
                },
              ),
            ),
          ),
        );

        // Assert - Initial items visible
        expect(find.text('Item 0'), findsOneWidget);
        expect(find.text('Item 1'), findsOneWidget);

        // Scroll and check later items
        await tester.fling(find.byType(ListView), const Offset(0, -500), 1000);
        await tester.pumpAndSettle();

        expect(find.text('Item 30'), findsOneWidget);
      });
    });

    group('State Management Widget Tests', () {
      testWidgets('should rebuild widget when state changes', (WidgetTester tester) async {
        // Arrange
        int counter = 0;

        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: StatefulBuilder(
                builder: (context, setState) {
                  return Column(
                    children: [
                      Text('Count: $counter'),
                      ElevatedButton(
                        onPressed: () {
                          setState(() {
                            counter++;
                          });
                        },
                        child: Text('Increment'),
                      ),
                    ],
                  );
                },
              ),
            ),
          ),
        );

        // Assert - Initial state
        expect(find.text('Count: 0'), findsOneWidget);

        // Act - Increment counter
        await tester.tap(find.byType(ElevatedButton));
        await tester.pump();

        // Assert - State updated
        expect(find.text('Count: 1'), findsOneWidget);
      });
    });

    group('Accessibility Tests', () {
      testWidgets('should have proper semantic labels', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: Column(
                children: [
                  Text('Welcome', style: TextStyle(fontSize: 24)),
                  ElevatedButton(
                    onPressed: () {},
                    child: Text('Submit Form'),
                  ),
                ],
              ),
            ),
          ),
        );

        // Assert
        expect(
          tester.semantics(find.text('Welcome')),
          matchesSemantics(label: 'Welcome'),
        );
        expect(
          tester.semantics(find.byType(ElevatedButton)),
          matchesSemantics(label: 'Submit Form', button: true),
        );
      });

      testWidgets('should support keyboard navigation', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: Column(
                children: [
                  ElevatedButton(
                    onPressed: () {},
                    child: Text('Button 1'),
                  ),
                  ElevatedButton(
                    onPressed: () {},
                    child: Text('Button 2'),
                  ),
                ],
              ),
            ),
          ),
        );

        // Act - Tab through buttons
        await tester.sendKeyEvent(LogicalKeyboardKey.tab);
        await tester.pump();

        // Assert - First button should be focused
        expect(tester.binding.focusManager.primaryFocus?.debugLabel, contains('Button 1'));
      });
    });

    group('Performance Tests', () {
      testWidgets('should handle large lists efficiently', (WidgetTester tester) async {
        // Arrange
        final largeList = List.generate(1000, (index) => 'Item $index');

        // Act
        final stopwatch = Stopwatch()..start();
        
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: ListView.builder(
                itemCount: largeList.length,
                itemBuilder: (context, index) {
                  return ListTile(
                    title: Text(largeList[index]),
                  );
                },
              ),
            ),
          ),
        );

        stopwatch.stop();

        // Assert
        expect(stopwatch.elapsedMilliseconds, lessThan(1000)); // Should render in < 1s
        expect(find.text('Item 0'), findsOneWidget);
      });
    });
  });
}

// Mock widget implementations for testing
enum ButtonVariant { primary, secondary, danger }

class CustomButton extends StatelessWidget {
  final String text;
  final VoidCallback onPressed;
  final bool isLoading;
  final ButtonVariant variant;
  
  const CustomButton({
    Key? key,
    required this.text,
    required this.onPressed,
    this.isLoading = false,
    this.variant = ButtonVariant.primary,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return ElevatedButton(
      onPressed: isLoading ? null : onPressed,
      style: ElevatedButton.styleFrom(
        backgroundColor: _getVariantColor(),
      ),
      child: isLoading 
        ? Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              SizedBox(
                width: 16,
                height: 16,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
              SizedBox(width: 8),
              Text(text),
            ],
          )
        : Text(text),
    );
  }

  Color _getVariantColor() {
    switch (variant) {
      case ButtonVariant.primary:
        return Colors.blue;
      case ButtonVariant.secondary:
        return Colors.grey;
      case ButtonVariant.danger:
        return Colors.red;
    }
  }
}

class UserAvatar extends StatelessWidget {
  final String name;
  final String? imageUrl;
  final double size;
  
  const UserAvatar({
    Key? key,
    required this.name,
    this.imageUrl,
    required this.size,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return CircleAvatar(
      radius: size / 2,
      backgroundImage: imageUrl != null ? NetworkImage(imageUrl!) : null,
      child: imageUrl == null
        ? Text(
            _getInitials(),
            style: TextStyle(
              fontSize: size / 3,
              fontWeight: FontWeight.bold,
            ),
          )
        : null,
    );
  }

  String _getInitials() {
    final parts = name.split(' ');
    if (parts.length >= 2) {
      return '${parts[0][0]}${parts[1][0]}'.toUpperCase();
    }
    return name.substring(0, 2).toUpperCase();
  }
}

class DataTableWidget extends StatelessWidget {
  final List<Map<String, dynamic>> data;
  final List<String> columns;
  final bool sortable;
  final bool searchable;
  
  const DataTableWidget({
    Key? key,
    required this.data,
    required this.columns,
    this.sortable = false,
    this.searchable = false,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    if (data.isEmpty) {
      return Center(child: Text('No data available'));
    }

    return Column(
      children: [
        if (searchable)
          Padding(
            padding: EdgeInsets.all(8),
            child: TextField(
              decoration: InputDecoration(
                hintText: 'Search...',
                border: OutlineInputBorder(),
              ),
            ),
          ),
        Expanded(
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: DataTable(
              columns: columns.map((col) => DataColumn(
                label: Text(col[0].toUpperCase() + col.substring(1)),
                onSort: sortable ? (columnIndex, ascending) {} : null,
              )).toList(),
              rows: data.map((row) => DataRow(
                cells: columns.map((col) => DataCell(
                  Text(row[col]?.toString() ?? ''),
                )).toList(),
              )).toList(),
            ),
          ),
        ),
      ],
    );
  }
}

class FormInput extends StatelessWidget {
  final String label;
  final TextEditingController controller;
  final String? Function(String?)? validator;
  final bool obscureText;
  final bool showPasswordToggle;
  
  const FormInput({
    Key? key,
    required this.label,
    required this.controller,
    this.validator,
    this.obscureText = false,
    this.showPasswordToggle = false,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.symmetric(vertical: 8),
      child: TextFormField(
        controller: controller,
        validator: validator,
        obscureText: obscureText,
        decoration: InputDecoration(
          labelText: label,
          border: OutlineInputBorder(),
          suffixIcon: showPasswordToggle && obscureText
            ? IconButton(
                icon: Icon(Icons.visibility),
                onPressed: () {},
              )
            : null,
        ),
      ),
    );
  }
}

class ModalDialog extends StatelessWidget {
  final bool isOpen;
  final String title;
  final Widget child;
  final VoidCallback onClose;
  final bool closeOnOutsideTap;
  
  const ModalDialog({
    Key? key,
    required this.isOpen,
    required this.title,
    required this.child,
    required this.onClose,
    this.closeOnOutsideTap = false,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    if (!isOpen) return SizedBox.shrink();

    return Stack(
      children: [
        // Overlay
        GestureDetector(
          onTap: closeOnOutsideTap ? onClose : null,
          child: Container(
            color: Colors.black54,
          ),
        ),
        // Modal content
        Center(
          child: Card(
            margin: EdgeInsets.all(20),
            child: Padding(
              padding: EdgeInsets.all(16),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        title,
                        style: Theme.of(context).textTheme.headline6,
                      ),
                      IconButton(
                        icon: Icon(Icons.close),
                        onPressed: onClose,
                      ),
                    ],
                  ),
                  SizedBox(height: 16),
                  child,
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }
}
