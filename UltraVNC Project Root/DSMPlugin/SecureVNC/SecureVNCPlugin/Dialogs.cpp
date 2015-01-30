/////////////////////////////////////////////////////////////////////////////
//  Copyright (C) 2005 Ultr@Vnc.  All Rights Reserved.
//  Copyright (C) 1998-2002 The OpenSSL Project.  All rights reserved.
//  Copyright (C) 2010 Adam D. Walling aka Adzm.  All Rights Reserved.
//
//  This product includes software developed by the OpenSSL Project for use 
//  in the OpenSSL Toolkit (http://www.openssl.org/)
//
////////////////////////////////////////////////////////////////////////////
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2.1 of the License, or (at your option) any later version.
// 
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
// 
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
//  USA.
//
//  LGPL - http://www.gnu.org/licenses/lgpl-2.1.html
//
// If the source code for the program is not available from the place from
// which you received this file, please refer to the addresses below:
//
// UltraVNC                 - http://ultravnc.sourceforge.net/
// OpenSSL                  - http://openssl.org 
// Adam D. Walling aka Adzm - http://adamwalling.com/SecureVNC/
//                          - http://sourceforge.net/projects/securevncplugin/
//                          - mailto:adam.walling@gmail.com
////////////////////////////////////////////////////////////////////////////

#include "StdAfx.h"
#include "Dialogs.h"
#include "Resource.h"
#include "CryptUtils.h"
#include "Utils.h"
#include "Commdlg.h"
#include "SecureVNCPlugin.h"
#include "IntegratedSecureVNCPluginObject.h"
#include <windowsx.h>

INT_PTR DoConfigDialog(HWND hwndParent)
{
    return DialogBoxParam(g_hInstance, MAKEINTRESOURCE(IDD_CONFIG_DLG), 
        hwndParent, (DLGPROC)ConfigDlgProc, NULL);
}

void GetAvailableKeyStatus(bool& bPrivateKeyAvailable, bool& bClientAuthPublicKeyAvailable, bool& bClientAuthPrivateKeyAvailable)
{
	bPrivateKeyAvailable = false;
	bClientAuthPublicKeyAvailable = false;
	bClientAuthPrivateKeyAvailable = false;

	HANDLE hFile;
	
	hFile = FindPrivateKeyFile();
	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE) {
		::CloseHandle(hFile);
		bPrivateKeyAvailable = true;
	} else {
		bPrivateKeyAvailable = false;
	}

	hFile = FindClientAuthPublicKeyFile();
	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE) {
		::CloseHandle(hFile);
		bClientAuthPublicKeyAvailable = true;
	} else {
		bClientAuthPublicKeyAvailable = false;
	}

	hFile = FindClientAuthPrivateKeyFile();
	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE) {
		::CloseHandle(hFile);
		bClientAuthPrivateKeyAvailable = true;
	} else {
		bClientAuthPrivateKeyAvailable = false;
	}
}

void UpdateStatusText(HWND hwnd)
{
	bool bPrivateKeyAvailable = false;
	bool bClientAuthPublicKeyAvailable = false;
	bool bClientAuthPrivateKeyAvailable = false;
	GetAvailableKeyStatus(bPrivateKeyAvailable, bClientAuthPublicKeyAvailable, bClientAuthPrivateKeyAvailable);

	TCHAR szInfo[1024];

	::ZeroMemory(szInfo, sizeof(szInfo));
	
	if (bPrivateKeyAvailable) {
		_tcscat_s(szInfo, sizeof(szInfo), _T("Server will use pre-generated private keyfile.\r\n"));
	} else {
		_tcscat_s(szInfo, sizeof(szInfo), _T("Server will automatically create a new private key.\r\n"));
	}

	if (bClientAuthPublicKeyAvailable) {
		_tcscat_s(szInfo, sizeof(szInfo), _T("Server will authenticate clients using pre-shared public key.\r\n"));
	}

	if (bPrivateKeyAvailable) {
		_tcscat_s(szInfo, sizeof(szInfo), _T("Clients will authenticate to server using pre-shared private key.\r\n"));
	}
	
	SetDlgItemText(hwnd, IDC_INFO, szInfo);
}

void ReflectRSACombo(HWND hwnd)
{
	int nRSACurSel = ComboBox_GetCurSel(GetDlgItem(hwnd, IDC_COMBO_RSA));
	if (nRSACurSel == 3) {
		// 512
		EnableWindow(GetDlgItem(hwnd, IDC_CHECK_448), FALSE);
		EnableWindow(GetDlgItem(hwnd, IDC_CHECK_256), FALSE);
		EnableWindow(GetDlgItem(hwnd, IDC_CHECK_192), FALSE);
		EnableWindow(GetDlgItem(hwnd, IDC_CHECK_128), TRUE);
		EnableWindow(GetDlgItem(hwnd, IDC_CHECK_56), TRUE);
	} else {
		EnableWindow(GetDlgItem(hwnd, IDC_CHECK_448), TRUE);
		EnableWindow(GetDlgItem(hwnd, IDC_CHECK_256), TRUE);
		EnableWindow(GetDlgItem(hwnd, IDC_CHECK_192), TRUE);
		EnableWindow(GetDlgItem(hwnd, IDC_CHECK_128), TRUE);
		EnableWindow(GetDlgItem(hwnd, IDC_CHECK_56), TRUE);
	}
}

void ReflectKeyOptions(HWND hwnd)
{
	DWORD dwFlags = 0;

	if (IsDlgButtonChecked(hwnd, IDC_CHECK_3AES)) {
		dwFlags |= (IntegratedSecureVNCPlugin::svncKey128 | IntegratedSecureVNCPlugin::svncKey192 | IntegratedSecureVNCPlugin::svncKey256);
	}
	if (IsDlgButtonChecked(hwnd, IDC_CHECK_AESCFB)) {
		dwFlags |= (IntegratedSecureVNCPlugin::svncKey128 | IntegratedSecureVNCPlugin::svncKey192 | IntegratedSecureVNCPlugin::svncKey256);
	}
	if (IsDlgButtonChecked(hwnd, IDC_CHECK_AES)) {
		dwFlags |= (IntegratedSecureVNCPlugin::svncKey128 | IntegratedSecureVNCPlugin::svncKey192 | IntegratedSecureVNCPlugin::svncKey256);
	}
	if (IsDlgButtonChecked(hwnd, IDC_CHECK_BF)) {
		dwFlags |= (IntegratedSecureVNCPlugin::svncKey56 | IntegratedSecureVNCPlugin::svncKey128 | IntegratedSecureVNCPlugin::svncKey192 | IntegratedSecureVNCPlugin::svncKey256 | IntegratedSecureVNCPlugin::svncKey448);
	}
	if (IsDlgButtonChecked(hwnd, IDC_CHECK_IDEA)) {
		dwFlags |= (IntegratedSecureVNCPlugin::svncKey128);
	}
	if (IsDlgButtonChecked(hwnd, IDC_CHECK_CAST5)) {
		dwFlags |= (IntegratedSecureVNCPlugin::svncKey56 | IntegratedSecureVNCPlugin::svncKey128);
	}
	if (IsDlgButtonChecked(hwnd, IDC_CHECK_ARC4)) {
		dwFlags |= (IntegratedSecureVNCPlugin::svncKey56 | IntegratedSecureVNCPlugin::svncKey128 | IntegratedSecureVNCPlugin::svncKey192 | IntegratedSecureVNCPlugin::svncKey256);
	}
				
	EnableWindow(GetDlgItem(hwnd, IDC_CHECK_448), (dwFlags & IntegratedSecureVNCPlugin::svncKey448) ? TRUE : FALSE);
	EnableWindow(GetDlgItem(hwnd, IDC_CHECK_256), (dwFlags & IntegratedSecureVNCPlugin::svncKey256) ? TRUE : FALSE);
	EnableWindow(GetDlgItem(hwnd, IDC_CHECK_192), (dwFlags & IntegratedSecureVNCPlugin::svncKey192) ? TRUE : FALSE);
	EnableWindow(GetDlgItem(hwnd, IDC_CHECK_128), (dwFlags & IntegratedSecureVNCPlugin::svncKey128) ? TRUE : FALSE);
	EnableWindow(GetDlgItem(hwnd, IDC_CHECK_56), (dwFlags & IntegratedSecureVNCPlugin::svncKey56) ? TRUE : FALSE);
}

bool IsDlgButtonCheckedAndEnabled(HWND hwnd, int nIDButton)
{
	return IsDlgButtonChecked(hwnd, nIDButton) && IsWindowEnabled(GetDlgItem(hwnd, nIDButton));
}

BOOL CALLBACK ConfigDlgProc(HWND hwnd,  UINT uMsg,  WPARAM wParam, LPARAM lParam )
{
	RAND_event(uMsg, wParam, lParam);

    switch (uMsg)
    {
    case WM_INITDIALOG:
        {
			HWND hwndTitle = GetDlgItem(hwnd, IDC_TITLE);
			HFONT hFont = (HFONT)SendMessage(hwndTitle, WM_GETFONT, 0, 0);
			if (hFont) {
				LOGFONT lf;
				if (GetObject(hFont, sizeof(LOGFONT), &lf)) {
					lf.lfWidth = 0;
					lf.lfHeight = (lf.lfHeight * 2);

#pragma message("TODO - GDI font leak")
					HFONT hNewFont = CreateFontIndirect(&lf);

					if (hNewFont) {
						SendMessage(hwndTitle, WM_SETFONT, (WPARAM)hNewFont, (LPARAM)TRUE);
					}
				}
			}

			HWND hwndSubTitle = GetDlgItem(hwnd, IDC_SUBTITLE);
			hFont = (HFONT)SendMessage(hwndSubTitle, WM_GETFONT, 0, 0);
			if (hFont) {
				LOGFONT lf;
				if (GetObject(hFont, sizeof(LOGFONT), &lf)) {
					lf.lfWidth = 0;
					lf.lfHeight = (lf.lfHeight * 8) / 6;

#pragma message("TODO - GDI font leak")
					HFONT hNewFont = CreateFontIndirect(&lf);

					if (hNewFont) {
						SendMessage(hwndSubTitle, WM_SETFONT, (WPARAM)hNewFont, (LPARAM)TRUE);
					}
				}
			}

			SetDlgItemText(hwnd, IDC_TITLE, _T("SecureVNCPlugin " VER_VERSION_STR));

			SetDlgItemText(hwnd, IDC_SUBTITLE, "Created by Adam D. Walling");

			UpdateStatusText(hwnd);

			Edit_LimitText(GetDlgItem(hwnd, IDC_EDIT_PASSPHRASE), 128);
			Edit_LimitText(GetDlgItem(hwnd, IDC_EDIT_CONFIRM), 128);

			HWND hwndCombo = GetDlgItem(hwnd, IDC_COMBO_RSA);
			ComboBox_AddString(hwndCombo, "RSA-3072");
			ComboBox_AddString(hwndCombo, "RSA-2048");
			ComboBox_AddString(hwndCombo, "RSA-1024");
			ComboBox_AddString(hwndCombo, "RSA-512");

			if (!g_bSupportsIntegrated || g_hostType < 0) {
				// disable options
				EnableWindow(GetDlgItem(hwnd, IDC_GROUP_CIPHERS), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_GROUP_KEYLENGTH), FALSE);
				
				EnableWindow(GetDlgItem(hwnd, IDC_CHECK_3AES), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_CHECK_AESCFB), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_CHECK_AES), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_CHECK_BF), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_CHECK_IDEA), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_CHECK_CAST5), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_CHECK_ARC4), FALSE);
				
				EnableWindow(GetDlgItem(hwnd, IDC_CHECK_448), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_CHECK_256), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_CHECK_192), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_CHECK_128), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_CHECK_56), FALSE);

				EnableWindow(GetDlgItem(hwnd, IDC_STATIC_PASSPHRASE), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_EDIT_PASSPHRASE), FALSE);

				EnableWindow(GetDlgItem(hwnd, IDC_STATIC_CONFIRM), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_EDIT_CONFIRM), FALSE);

				EnableWindow(GetDlgItem(hwnd, IDC_COMBO_RSA), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_CHECK_LOW_KEY), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_CHECK_NEW_KEY), FALSE);
			} else {
				ConfigHelper configHelper(g_szConfig);

				if (0 == IntegratedSecureVNCPlugin::CheckBestSupportedFlags(configHelper.m_dwFlags)) {
					// Something must be messed up in the settings. Just include svncCipherAES | svncKey256
					configHelper.m_dwFlags |= (IntegratedSecureVNCPlugin::svncCipherAES | IntegratedSecureVNCPlugin::svncKey256 | IntegratedSecureVNCPlugin::svncConfigNewKey);
				}

				if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncCipher3AESOFB) {
					CheckDlgButton(hwnd, IDC_CHECK_3AES, BST_CHECKED);
				}
				if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncCipherAESCFB) {
					CheckDlgButton(hwnd, IDC_CHECK_AESCFB, BST_CHECKED);
				}
				if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncCipherAES) {
					CheckDlgButton(hwnd, IDC_CHECK_AES, BST_CHECKED);
				}
				if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncCipherBlowfish) {
					CheckDlgButton(hwnd, IDC_CHECK_BF, BST_CHECKED);
				}
				if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncCipherIDEA) {
					CheckDlgButton(hwnd, IDC_CHECK_IDEA, BST_CHECKED);
				}
				if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncCipherCAST5) {
					CheckDlgButton(hwnd, IDC_CHECK_CAST5, BST_CHECKED);
				}
				if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncCipherARC4) {
					CheckDlgButton(hwnd, IDC_CHECK_ARC4, BST_CHECKED);
				}

				if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncKey448) {
					CheckDlgButton(hwnd, IDC_CHECK_448, BST_CHECKED);
				}
				if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncKey256) {
					CheckDlgButton(hwnd, IDC_CHECK_256, BST_CHECKED);
				}
				if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncKey192) {
					CheckDlgButton(hwnd, IDC_CHECK_192, BST_CHECKED);
				}
				if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncKey128) {
					CheckDlgButton(hwnd, IDC_CHECK_128, BST_CHECKED);
				} 
				if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncKey56) {
					CheckDlgButton(hwnd, IDC_CHECK_56, BST_CHECKED);
				} 

				if (configHelper.m_szPassphrase && strlen(configHelper.m_szPassphrase) > 0) {
					SetDlgItemText(hwnd, IDC_EDIT_PASSPHRASE, configHelper.m_szPassphrase);
					SetDlgItemText(hwnd, IDC_EDIT_CONFIRM, configHelper.m_szPassphrase);
				}

				if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncConfigRSA1024) {
					ComboBox_SetCurSel(GetDlgItem(hwnd, IDC_COMBO_RSA), 2);
				} else if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncConfigRSA512) {
					ComboBox_SetCurSel(GetDlgItem(hwnd, IDC_COMBO_RSA), 3);
				} else if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncConfigRSA3072) {
					ComboBox_SetCurSel(GetDlgItem(hwnd, IDC_COMBO_RSA), 0);
				} else {
					ComboBox_SetCurSel(GetDlgItem(hwnd, IDC_COMBO_RSA), 1);
				}

				if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncConfigLowKey) {
					CheckDlgButton(hwnd, IDC_CHECK_LOW_KEY, BST_CHECKED);
				}
				if (configHelper.m_dwFlags & IntegratedSecureVNCPlugin::svncConfigNewKey) {
					CheckDlgButton(hwnd, IDC_CHECK_NEW_KEY, BST_CHECKED);
				}

				ReflectKeyOptions(hwnd);
				ReflectRSACombo(hwnd);
			}

            return TRUE;
        }
		
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDOK:
        case IDCANCEL:
			if (HIWORD(wParam) == BN_CLICKED) {
				if (!g_bSupportsIntegrated || g_hostType < 0) {
					EndDialog(hwnd, TRUE);
					return TRUE;
				}

				char szBuffer[256];
				szBuffer[0] = '\0';
				GetDlgItemText(hwnd, IDC_EDIT_PASSPHRASE, szBuffer, 256 - 1);
				size_t length = strlen(szBuffer);
				if (length > 0 && length <= 8) {
					if (IDNO == ::MessageBox(hwnd, "You should be using a longer passphrase; this one is too short! You are likely to be eaten by a grue. Do you want to continue?", "SecureVNCPlugin", MB_ICONSTOP | MB_YESNO)) {
						return TRUE;
					}
				}

				char szBufferConfirm[256];
				szBufferConfirm[0] = '\0';
				GetDlgItemText(hwnd, IDC_EDIT_CONFIRM, szBufferConfirm, 256 - 1);
				if (0 != strcmp(szBuffer, szBufferConfirm)) {
					::MessageBox(hwnd, "Your passphrases do not match. Please enter them again.", "SecureVNCPlugin", MB_ICONSTOP);
					return TRUE;
				}

				g_szNewConfig[0] = '\0';
				DWORD dwFlags = 0;
				{
					if (IsDlgButtonCheckedAndEnabled(hwnd, IDC_CHECK_3AES)) {
						dwFlags |= IntegratedSecureVNCPlugin::svncCipher3AESOFB;
					}
					if (IsDlgButtonCheckedAndEnabled(hwnd, IDC_CHECK_AESCFB)) {
						dwFlags |= IntegratedSecureVNCPlugin::svncCipherAESCFB;
					}
					if (IsDlgButtonCheckedAndEnabled(hwnd, IDC_CHECK_AES)) {
						dwFlags |= IntegratedSecureVNCPlugin::svncCipherAES;
					}
					if (IsDlgButtonCheckedAndEnabled(hwnd, IDC_CHECK_BF)) {
						dwFlags |= IntegratedSecureVNCPlugin::svncCipherBlowfish;
					}
					if (IsDlgButtonCheckedAndEnabled(hwnd, IDC_CHECK_IDEA)) {
						dwFlags |= IntegratedSecureVNCPlugin::svncCipherIDEA;
					}
					if (IsDlgButtonCheckedAndEnabled(hwnd, IDC_CHECK_CAST5)) {
						dwFlags |= IntegratedSecureVNCPlugin::svncCipherCAST5;
					}
					if (IsDlgButtonCheckedAndEnabled(hwnd, IDC_CHECK_ARC4)) {
						dwFlags |= IntegratedSecureVNCPlugin::svncCipherARC4;
					}


					if (IsDlgButtonCheckedAndEnabled(hwnd, IDC_CHECK_448)) {
						dwFlags |= IntegratedSecureVNCPlugin::svncKey448;
					}
					if (IsDlgButtonCheckedAndEnabled(hwnd, IDC_CHECK_256)) {
						dwFlags |= IntegratedSecureVNCPlugin::svncKey256;
					}
					if (IsDlgButtonCheckedAndEnabled(hwnd, IDC_CHECK_192)) {
						dwFlags |= IntegratedSecureVNCPlugin::svncKey192;
					}
					if (IsDlgButtonCheckedAndEnabled(hwnd, IDC_CHECK_128)) {
						dwFlags |= IntegratedSecureVNCPlugin::svncKey128;
					}
					if (IsDlgButtonCheckedAndEnabled(hwnd, IDC_CHECK_56)) {
						dwFlags |= IntegratedSecureVNCPlugin::svncKey56;
					}
					
					int nRSACurSel = ComboBox_GetCurSel(GetDlgItem(hwnd, IDC_COMBO_RSA));
					DebugLog("nRSACurSel %li\r\n", nRSACurSel);
					if (nRSACurSel == 0) {
						dwFlags |= IntegratedSecureVNCPlugin::svncConfigRSA3072;
					} else if (nRSACurSel == 2) {
						dwFlags |= IntegratedSecureVNCPlugin::svncConfigRSA1024;
					} else if (nRSACurSel == 3) {
						dwFlags |= IntegratedSecureVNCPlugin::svncConfigRSA512;
					}
					
					if (IsDlgButtonCheckedAndEnabled(hwnd, IDC_CHECK_LOW_KEY)) {
						dwFlags |= IntegratedSecureVNCPlugin::svncConfigLowKey;
						dwFlags |= IntegratedSecureVNCPlugin::svncConfigNewKey;
					}
					if (IsDlgButtonCheckedAndEnabled(hwnd, IDC_CHECK_NEW_KEY)) {
						dwFlags |= IntegratedSecureVNCPlugin::svncConfigNewKey;
					}
				}
				

				if (0 == IntegratedSecureVNCPlugin::CheckBestSupportedFlags(dwFlags)) {
					MessageBox(hwnd, "The options chosen are invalid. Please ensure a proper cipher and key length are enabled.", "SecureVNCPlugin", MB_ICONSTOP);
					return TRUE;
				}

				if ( (dwFlags & IntegratedSecureVNCPlugin::svncCipher3AESOFB) && !(dwFlags & IntegratedSecureVNCPlugin::svncConfigNewKey) ) {					
					MessageBox(hwnd, "3AES cannot be used without enabling the 'new key' option.", "SecureVNCPlugin", MB_ICONSTOP);
					return TRUE;
				}

				ConfigHelper configHelper(dwFlags, szBuffer);
				strcpy_s(g_szNewConfig, sizeof(g_szNewConfig), configHelper.m_szConfig);
				EndDialog(hwnd, TRUE);
            
				return TRUE;
			}
			break;
        case IDC_GENERATE_KEY:
			if (HIWORD(wParam) == BN_CLICKED) {
				if (IDCANCEL == ::MessageBox(hwnd, 
					"In most situations this is unncessary. Keys are normally generated automatically. You should only continue if you know what you are doing.", "SecureVNCPlugin", MB_ICONSTOP | MB_OKCANCEL))
				{
					return TRUE;
				}

				TCHAR szModulePath[_MAX_PATH];
				TCHAR szFilePath[_MAX_PATH];
				::ZeroMemory(szFilePath, sizeof(TCHAR) * _MAX_PATH);

				_tcscpy_s(szFilePath, sizeof(szFilePath) - 2, _T("Server_SecureVNC.pkey"));

				OPENFILENAME ofn;
				::ZeroMemory(&ofn, sizeof(ofn));
				ofn.lStructSize = sizeof(ofn);
				ofn.hwndOwner = hwnd;
				ofn.lpstrTitle = _T("Secure VNC Private Key for Server");
				ofn.lpstrFile = szFilePath;
				ofn.lpstrFilter = _T("Private Key Files (*.pkey)\0*.pkey\0\0");
                ofn.nMaxFile = _MAX_PATH;
                ofn.Flags = OFN_OVERWRITEPROMPT;
				if (GetModuleFileName(g_hInstance, szModulePath, _MAX_PATH - 1 - 1)) {
					TCHAR* lastFolderSeparator = _tcsrchr(szModulePath, '\\');
					if (lastFolderSeparator) {
						*lastFolderSeparator = '\0';
						ofn.lpstrInitialDir = szModulePath;
					}
				}
				if (GetSaveFileName(&ofn)) {
					RAND_screen();
					
					int nRSASize = 256;
					int nRSACurSel = ComboBox_GetCurSel(GetDlgItem(hwnd, IDC_COMBO_RSA));
					if (nRSACurSel == 0) {
						nRSASize = 384;
					} else if (nRSACurSel == 2) {
						nRSASize = 128;
					} else if (nRSACurSel == 3) {
						nRSASize = 64;
					}

					RSA* rsa = CreateRSAPrivateKeyFile(nRSASize, szFilePath);
					RSA_free(rsa);						
				}
				
				return TRUE;
			}
			break;
        case IDC_GENERATE_VIEWER_KEY:
			if (HIWORD(wParam) == BN_CLICKED) {
				::MessageBox(hwnd, 
					"The data preceeding the first underscore '_' character is used as an identifier of the client authentication key. "
					"It defaults to the current date, but can be modified. It should contain only standard characters (a-z0-9). "
					"The viewer will choose the private key according to this identifier, but will fall back to the first available if "
					"it cannot be matched. This allows you to update your client authentication keys without breaking the ability to "
					"connect to servers that may still be using an old key.", "SecureVNCPlugin", MB_ICONINFORMATION);

				TCHAR szModulePath[_MAX_PATH];
				TCHAR szFilePath[_MAX_PATH];
				::ZeroMemory(szFilePath, sizeof(TCHAR) * _MAX_PATH);

				SYSTEMTIME st;
				::GetLocalTime(&st);

				_snprintf_s(szFilePath, sizeof(szFilePath) - 1 - 1, _TRUNCATE, "%04d%02d%02d_Viewer_ClientAuth.pkey", st.wYear, st.wMonth, st.wDay);

				//_tcscpy_s(szFilePath, sizeof(szFilePath) - 2, _T("Viewer_ClientAuth.pkey"));

				OPENFILENAME ofn;
				::ZeroMemory(&ofn, sizeof(ofn));
				ofn.lStructSize = sizeof(ofn);
				ofn.hwndOwner = hwnd;
				ofn.lpstrTitle = _T("Client Authorization Private Key for Viewer");
				ofn.lpstrFile = szFilePath;
				ofn.lpstrFilter = _T("Private Key Files (*.pkey)\0*.pkey\0\0");
                ofn.nMaxFile = _MAX_PATH;
                ofn.Flags = OFN_OVERWRITEPROMPT;
				if (GetModuleFileName(g_hInstance, szModulePath, _MAX_PATH - 1 - 1)) {
					TCHAR* lastFolderSeparator = _tcsrchr(szModulePath, '\\');
					if (lastFolderSeparator) {
						*lastFolderSeparator = '\0';
						ofn.lpstrInitialDir = szModulePath;
					}
				}
				if (GetSaveFileName(&ofn)) {
					RAND_screen();
					
					int nRSASize = 256;
					int nRSACurSel = ComboBox_GetCurSel(GetDlgItem(hwnd, IDC_COMBO_RSA));
					if (nRSACurSel == 0) {
						nRSASize = 384;
					} else if (nRSACurSel == 2) {
						nRSASize = 128;
					} else if (nRSACurSel == 3) {
						nRSASize = 64;
					}

					RSA* rsa = CreateRSAPrivateKeyFile(nRSASize, szFilePath);
					
					if (rsa) {						
						_snprintf_s(szFilePath, sizeof(szFilePath) - 1 - 1, _TRUNCATE, "%04d%02d%02d_Server_ClientAuth.pubkey", st.wYear, st.wMonth, st.wDay);

						//_tcscpy_s(szFilePath, sizeof(szFilePath) - 2, _T("Server_ClientAuth.pubkey"));

						ofn.lpstrTitle = _T("Client Authorization Public Key for Server");
						ofn.lpstrFile = szFilePath;
						ofn.lpstrFilter = _T("Public Key Files (*.pubkey)\0*.pubkey\0\0");
						if (GetSaveFileName(&ofn)) {
							CreateRSAPublicKeyFile(rsa, szFilePath);
						}
						
						RSA_free(rsa);
					}
				}

				return TRUE;				
			}
			break;
			
        case IDC_WEBSITE:
			if (HIWORD(wParam) == BN_CLICKED) {
				ShellExecute(NULL, NULL, _T("http://adamwalling.com/SecureVNC"), NULL, NULL, SW_SHOWNORMAL);
				
				return TRUE;
			}
			break;

		case IDC_COMBO_RSA:
			if (HIWORD(wParam) == CBN_SELCHANGE) {

				ReflectKeyOptions(hwnd);
				ReflectRSACombo(hwnd);

				bool bPrivateKeyAvailable = false;
				bool bClientAuthPublicKeyAvailable = false;
				bool bClientAuthPrivateKeyAvailable = false;
				GetAvailableKeyStatus(bPrivateKeyAvailable, bClientAuthPublicKeyAvailable, bClientAuthPrivateKeyAvailable);

				
				if (bPrivateKeyAvailable || bClientAuthPublicKeyAvailable || bClientAuthPrivateKeyAvailable) {
					TCHAR szInfo[1024];
					::ZeroMemory(szInfo, sizeof(szInfo));
					
					_tcscat_s(szInfo, sizeof(szInfo), _T("This option only applies to newly-generated RSA keys."));

					if (bPrivateKeyAvailable) {
						_tcscat_s(szInfo, sizeof(szInfo), _T("\r\n\r\nSince you are using a pre-generated private keyfile, you must create a new keyfile to change the size of the RSA key. Alternatively, removing the pre-generated keyfile will automatically cause a new temporary RSA key to be generated upon each connection."));
					}
					if (bClientAuthPublicKeyAvailable || bClientAuthPrivateKeyAvailable) {
						_tcscat_s(szInfo, sizeof(szInfo), _T("\r\n\r\nSince you are using a pre-shared public key for client authentication, you must create a new pair of client authentication keyfiles to change the size of the RSA keys."));
					}
					
					MessageBox(hwnd, szInfo, "SecureVNCPlugin", MB_ICONINFORMATION);
				}

				return TRUE;
			}
			break;

		case IDC_CHECK_3AES:
		case IDC_CHECK_AESCFB:
		case IDC_CHECK_AES:
		case IDC_CHECK_BF:
		case IDC_CHECK_IDEA:
		case IDC_CHECK_CAST5:
		case IDC_CHECK_ARC4:
			if (HIWORD(wParam) == BN_CLICKED) {

				ReflectKeyOptions(hwnd);
				ReflectRSACombo(hwnd);

				return TRUE;
			}
			break;
		case IDC_CHECK_NEW_KEY:
			if (HIWORD(wParam) == BN_CLICKED) {
				if (!IsDlgButtonChecked(hwnd, IDC_CHECK_NEW_KEY)) {
					CheckDlgButton(hwnd, IDC_CHECK_LOW_KEY, BST_UNCHECKED);
				}
				return TRUE;
			}
			break;
		case IDC_CHECK_LOW_KEY:
			if (HIWORD(wParam) == BN_CLICKED) {
				if (IsDlgButtonChecked(hwnd, IDC_CHECK_LOW_KEY)) {
					CheckDlgButton(hwnd, IDC_CHECK_NEW_KEY, BST_CHECKED);
				}
			}
			break;
        }
        break;
    }
    return FALSE;
}