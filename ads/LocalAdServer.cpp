#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#pragma comment(lib,"Ws2_32.lib")
namespace fs=std::filesystem;
static const unsigned short PORT=8765;
static std::string AdminPage(){return R"HTML(<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>PCPM — Реклама</title><style>body{font:16px Segoe UI,Arial;background:#101a2c;color:#e8f1ff;max-width:900px;margin:40px auto;padding:0 20px}textarea{width:100%;height:260px;background:#192943;color:#fff;border:1px solid #52708f;padding:12px;box-sizing:border-box}button{background:#167ca8;color:white;border:0;padding:12px 22px;margin:12px 0;cursor:pointer}small{color:#9eb5cc}a{color:#75c8ff}</style><h1>Управление рекламой</h1><p>Одна строка — один баннер. Формат: <b>Заголовок|URL рекламодателя|интервал_секунд</b></p><textarea id="data" spellcheck="false"></textarea><br><button onclick="save()">Сохранить баннеры</button><button onclick="load()">Обновить</button><p id="status"></p><small>Сервер принимает соединения только с этого компьютера (127.0.0.1). Ссылки рекламодателей должны начинаться с https:// или http://.</small><script>async function load(){let r=await fetch('/api/banners.tsv');document.querySelector('#data').value=await r.text();document.querySelector('#status').textContent='Конфигурация загружена'}async function save(){let r=await fetch('/api/banners.tsv',{method:'POST',headers:{'Content-Type':'text/plain; charset=utf-8'},body:document.querySelector('#data').value});document.querySelector('#status').textContent=r.ok?'Сохранено':'Ошибка сохранения'}load();</script></html>)HTML";}
static std::string ReadFile(const fs::path&p){std::ifstream f(p,std::ios::binary);return f?std::string((std::istreambuf_iterator<char>(f)),{}):std::string{};}
static void Send(SOCKET s,int code,const char*type,const std::string&body){std::ostringstream h;h<<"HTTP/1.1 "<<code<<(code==200?" OK":" Error")<<"\r\nContent-Type: "<<type<<"\r\nContent-Length: "<<body.size()<<"\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n";auto x=h.str()+body;send(s,x.data(),(int)x.size(),0);}
int main(){
 WSADATA w{};if(WSAStartup(MAKEWORD(2,2),&w))return 1;
 SOCKET srv=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(srv==INVALID_SOCKET)return 2;
 sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(PORT);InetPtonA(AF_INET,"127.0.0.1",&a.sin_addr);
 if(bind(srv,(sockaddr*)&a,sizeof(a))==SOCKET_ERROR||listen(srv,8)==SOCKET_ERROR){std::cerr<<"Cannot bind 127.0.0.1:"<<PORT<<"\n";closesocket(srv);WSACleanup();return 3;}
 fs::path dir=fs::path(getenv("LOCALAPPDATA")?getenv("LOCALAPPDATA"):"." )/"PCPerformanceMonitor"/"ads";fs::create_directories(dir);fs::path data=dir/"banners.tsv";
 if(!fs::exists(data)){std::ofstream f(data);f<<"Пример рекламного баннера|https://example.com|10\n";}
 std::cout<<"PCPM local ad server: http://127.0.0.1:"<<PORT<<"/admin\n";
 for(;;){SOCKET c=accept(srv,nullptr,nullptr);if(c==INVALID_SOCKET)continue;std::string req;char b[4096];int n;
  while((n=recv(c,b,sizeof(b),0))>0){req.append(b,n);auto p=req.find("\r\n\r\n");if(p!=std::string::npos){size_t len=0;auto cl=req.find("Content-Length:");if(cl!=std::string::npos){cl+=15;while(cl<req.size()&&req[cl]==' ')++cl;len=(size_t)std::stoul(req.substr(cl));}if(req.size()>=p+4+len)break;}}
  auto e=req.find("\r\n");std::string first=req.substr(0,e);auto h=req.find("\r\n\r\n");std::string body=h==std::string::npos?"":req.substr(h+4);
  if(first.rfind("GET /admin ",0)==0)Send(c,200,"text/html; charset=utf-8",AdminPage());
  else if(first.rfind("GET /api/banners.tsv ",0)==0)Send(c,200,"text/plain; charset=utf-8",ReadFile(data));
  else if(first.rfind("POST /api/banners.tsv ",0)==0){
   if(body.size()>65536)Send(c,413,"text/plain","Too large");
   else {std::istringstream in(body);std::string line;bool valid=true;while(std::getline(in,line)){if(line.size()>2048||line.find('|')==std::string::npos){valid=false;break;}auto p=line.find('|');auto q=line.find('|',p+1);std::string url=line.substr(p+1,q==std::string::npos?q:q-p-1);if(url.rfind("https://",0)!=0&&url.rfind("http://",0)!=0){valid=false;break;}}if(valid){std::ofstream f(data,std::ios::binary|std::ios::trunc);f<<body;Send(c,200,"text/plain","Saved");}else Send(c,400,"text/plain","Invalid format or URL");}
  } else Send(c,404,"text/plain","Not found");
  shutdown(c,SD_BOTH);closesocket(c);
 }
}
