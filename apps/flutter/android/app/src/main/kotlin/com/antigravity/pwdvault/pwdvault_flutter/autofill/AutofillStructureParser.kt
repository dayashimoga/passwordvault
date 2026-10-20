package com.antigravity.pwdvault.pwdvault_flutter.autofill

import android.app.assist.AssistStructure
import android.os.Build
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import androidx.annotation.RequiresApi

/**
 * Parsed form fields and security origin metadata extracted from an Android AssistStructure.
 */
data class ParsedAutofillStructure(
    val webDomain: String?,
    val packageName: String?,
    val usernameId: AutofillId?,
    val passwordId: AutofillId?,
    val isPasswordFieldPresent: Boolean = passwordId != null
)

/**
 * High-assurance AssistStructure parser traversing ViewNodes to locate credential fields.
 */
@RequiresApi(Build.VERSION_CODES.O)
object AutofillStructureParser {

    fun parse(structure: AssistStructure): ParsedAutofillStructure {
        var webDomain: String? = null
        var packageName: String? = null
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null

        val windowCount = structure.windowNodeCount
        for (w in 0 until windowCount) {
            val window = structure.getWindowNodeAt(w)
            val root = window.rootViewNode
            val result = traverseNode(root)

            if (webDomain == null && result.webDomain != null) {
                webDomain = result.webDomain
            }
            if (packageName == null && result.packageName != null) {
                packageName = result.packageName
            }
            if (usernameId == null && result.usernameId != null) {
                usernameId = result.usernameId
            }
            if (passwordId == null && result.passwordId != null) {
                passwordId = result.passwordId
            }
        }

        return ParsedAutofillStructure(
            webDomain = webDomain,
            packageName = packageName ?: structure.activityComponent?.packageName,
            usernameId = usernameId,
            passwordId = passwordId
        )
    }

    private fun traverseNode(node: AssistStructure.ViewNode): ParsedAutofillStructure {
        var webDomain = node.webDomain
        var packageName = node.idPackage
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null

        // Detect password fields
        val hints = node.autofillHints
        val isPasswordHint = hints?.any { it.equals(View.AUTOFILL_HINT_PASSWORD, ignoreCase = true) } == true
        val inputType = node.inputType
        val isPasswordInputType = (inputType and InputType.TYPE_MASK_CLASS) == InputType.TYPE_CLASS_TEXT && (
                (inputType and InputType.TYPE_TEXT_VARIATION_PASSWORD) == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                (inputType and InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD) == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
        )

        val idEntry = node.idEntry?.lowercase() ?: ""
        val hintText = node.hint?.lowercase() ?: ""

        if (isPasswordHint || isPasswordInputType || idEntry.contains("password") || hintText.contains("password")) {
            passwordId = node.autofillId
        } else {
            // Detect username / email fields
            val isUsernameHint = hints?.any {
                it.equals(View.AUTOFILL_HINT_USERNAME, ignoreCase = true) ||
                it.equals(View.AUTOFILL_HINT_EMAIL_ADDRESS, ignoreCase = true)
            } == true
            val isEmailInputType = (inputType and InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS) == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS

            if (isUsernameHint || isEmailInputType || idEntry.contains("user") || idEntry.contains("email") ||
                hintText.contains("username") || hintText.contains("email")) {
                usernameId = node.autofillId
            }
        }

        // Recurse children
        for (i in 0 until node.childCount) {
            val child = node.getChildAt(i)
            val childResult = traverseNode(child)

            if (webDomain == null && childResult.webDomain != null) {
                webDomain = childResult.webDomain
            }
            if (packageName == null && childResult.packageName != null) {
                packageName = childResult.packageName
            }
            if (usernameId == null && childResult.usernameId != null) {
                usernameId = childResult.usernameId
            }
            if (passwordId == null && childResult.passwordId != null) {
                passwordId = childResult.passwordId
            }
        }

        return ParsedAutofillStructure(
            webDomain = webDomain,
            packageName = packageName,
            usernameId = usernameId,
            passwordId = passwordId
        )
    }
}
