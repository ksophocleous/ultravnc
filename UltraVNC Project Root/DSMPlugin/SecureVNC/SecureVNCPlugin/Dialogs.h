#pragma once

#include "shellapi.h"
#pragma comment(lib, "shell32.lib")

// Dialog Procedures
BOOL CALLBACK ConfigDlgProc(HWND hwnd,  UINT uMsg,  WPARAM wParam, LPARAM lParam );
INT_PTR DoConfigDialog(HWND hwndParent);
