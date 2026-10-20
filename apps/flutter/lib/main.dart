import 'package:flutter/material.dart';
import 'core/theme/app_theme.dart';
import 'services/vault_state.dart';
import 'views/unlock_view.dart';
import 'views/vault_shell.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const PwdVaultApp());
}

/// Root application widget for PwdVault.
class PwdVaultApp extends StatelessWidget {
  const PwdVaultApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'PwdVault',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      themeMode: ThemeMode.dark,
      home: ListenableBuilder(
        listenable: VaultState.instance,
        builder: (context, _) {
          final state = VaultState.instance;
          if (state.isLocked) {
            return const UnlockView();
          } else {
            return const VaultShell();
          }
        },
      ),
    );
  }
}
