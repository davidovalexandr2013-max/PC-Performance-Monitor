    SetBkMode(d->hDC,TRANSPARENT); SetTextColor(d->hDC,RGB(255,255,255));
    wchar_t label[256]{}; GetWindowTextW(d->hwndItem,label,256);
    DrawTextW(d->hDC,label,-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    if(d->itemState&ODS_FOCUS) { InflateRect(&r,-4,-4); DrawFocusRect(d->hDC,&r); }
}
static void SaveReport() {
    wchar_t file[MAX_PATH]=L"PC_Performance_Report.txt";
    OPENFILENAMEW ofn{}; ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=g_window; ofn.lpstrFilter=L"Текстовые файлы (*.txt)\0*.txt\0Все файлы\0*.*\0";
    ofn.lpstrFile=file; ofn.nMaxFile=MAX_PATH; ofn.Flags=OFN_OVERWRITEPROMPT|OFN_PATHMUSTEXIST; ofn.lpstrDefExt=L"txt";
    if(GetSaveFileNameW(&ofn)) {
        int n=GetWindowTextLengthW(g_output); std::wstring s(n+1,L'\0'); GetWindowTextW(g_output,s.data(),n+1); s.resize(n);
        std::wofstream f(file);
        if(f) {
            f << s << L"\r\n\r\n=== АВТОМАТИЧЕСКИЙ ЖУРНАЛ ТЕКУЩЕГО СЕАНСА ===\r\n";
            std::lock_guard<std::mutex> lock(g_sessionMutex);
            std::wifstream log(g_sessionLogPath);
            if(log) f << log.rdbuf();
            else f << L"Журнал текущего сеанса недоступен.\r\n";
            SetStatus(L"Отчёт и журнал сеанса сохранены");
        } else {
            SetStatus(L"Не удалось сохранить отчёт");
            SessionLog(L"REPORT_SAVE_ERROR | " + std::to_wstring(GetLastError()));
        }
    }
}
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch(msg) {
    case WM_CREATE: {
        g_window=hwnd;
        SetTimer(hwnd, 1, 2000, nullptr);
        SessionLog(L"MAIN_WINDOW_CREATED");
        CaptureProcessActivity();
        AddButton(hwnd,L"Оборудование",ID_HARDWARE,10,10);
        AddButton(hwnd,L"SMART / NVMe",ID_SMART,168,10);
        AddButton(hwnd,L"Диски",ID_DISKS,326,10);