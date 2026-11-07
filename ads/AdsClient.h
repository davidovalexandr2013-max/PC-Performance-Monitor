#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>

namespace PCPMAds {
struct Banner { std::wstring title,url; unsigned seconds=10; };
inline std::vector<Banner>& Items(){static std::vector<Banner> v;return v;}
inline size_t& Current(){static size_t i=0;return i;}
inline bool ValidUrl(const std::wstring&u){return u.rfind(L"https://",0)==0||u.rfind(L"http://",0)==0;}
inline bool Refresh(){
 HINTERNET s=WinHttpOpen(L"PCPerformanceMonitor/1.4.1",WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
 if(!s)return false;
 WinHttpSetTimeouts(s,1000,1000,1500,1500);
 HINTERNET c=WinHttpConnect(s,L"127.0.0.1",8765,0);
 HINTERNET r=c?WinHttpOpenRequest(c,L"GET",L"/api/banners.tsv",nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,0):nullptr;
 bool ok=r&&WinHttpSendRequest(r,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0)&&WinHttpReceiveResponse(r,nullptr);
 std::string bytes;
 if(ok){DWORD avail=0,got=0;char b[2048];while(WinHttpQueryDataAvailable(r,&avail)&&avail){DWORD take=(std::min<DWORD>)(avail,sizeof(b));if(!WinHttpReadData(r,b,take,&got)||!got)break;bytes.append(b,got);}}
 if(r)WinHttpCloseHandle(r);if(c)WinHttpCloseHandle(c);WinHttpCloseHandle(s);
 if(!ok||bytes.empty())return false;
 int n=MultiByteToWideChar(CP_UTF8,0,bytes.data(),(int)bytes.size(),nullptr,0);if(!n)return false;
 std::wstring content(n,L'\0');MultiByteToWideChar(CP_UTF8,0,bytes.data(),(int)bytes.size(),content.data(),n);
 std::vector<Banner> next;std::wistringstream in(content);std::wstring line;
 while(std::getline(in,line)){if(!line.empty()&&line.back()==L'\r')line.pop_back();auto p=line.find(L'|');if(p==std::wstring::npos)continue;auto q=line.find(L'|',p+1);Banner b;b.title=line.substr(0,p);b.url=line.substr(p+1,q==std::wstring::npos?q:q-p-1);if(!ValidUrl(b.url))continue;if(q!=std::wstring::npos){try{b.seconds=(unsigned)std::stoul(line.substr(q+1));}catch(...){b.seconds=10;}}b.seconds=(std::max)(5u,(std::min)(b.seconds,300u));if(!b.title.empty())next.push_back(std::move(b));}
 if(next.empty())return false;Items()=std::move(next);Current()%=Items().size();return true;
}
inline std::wstring Label(){if(Items().empty())return L"Реклама: локальный сервер не подключён";return L"Реклама  •  "+Items()[Current()].title+L"   —   Нажмите, чтобы открыть сайт рекламодателя";}
inline unsigned Interval(){return Items().empty()?30:Items()[Current()].seconds;}
inline void Rotate(){if(!Items().empty())Current()=(Current()+1)%Items().size();}
inline bool Open(){if(Items().empty())return false;const auto&u=Items()[Current()].url;if(!ValidUrl(u))return false;return (INT_PTR)ShellExecuteW(nullptr,L"open",u.c_str(),nullptr,nullptr,SW_SHOWNORMAL)>32;}
}
