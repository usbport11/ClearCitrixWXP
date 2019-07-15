#include <cstdlib>
#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <vector>

//exe files
#define CONCENTR "concentr.exe"
#define WFCRUN "wfcrun32.exe"
#define REDIR "redirector.exe"
#define SELFSER "SelfServicePlugin.exe"
#define RECEIVER "Receiver.exe"

//directory
#define MAINDIR "C:\\Program Files\\Citrix"
#define COMMON "C:\\Program Files\\Common Files\\Citrix"

using namespace std;

vector <string> HKCR_Keys;
vector <string> HKLM_Keys;

bool CreateKeysList()
{    
  HKCR_Keys.push_back(".cr");
  HKCR_Keys.push_back(".ica");
  HKCR_Keys.push_back("Citrix.AuthManager");
  HKCR_Keys.push_back("Citrix.AuthManager.5");
  HKCR_Keys.push_back("Citrix.AuthSingleUseFactory");
  HKCR_Keys.push_back("Citrix.AuthSingleUseFactory.4");
  HKCR_Keys.push_back("Citrix.ICAClient");
  HKCR_Keys.push_back("Citrix.ICAClient.2.1");
  HKCR_Keys.push_back("Citrix.ICAClient.2.2");
  HKCR_Keys.push_back("Citrix.ICAClient.2.3");
  HKCR_Keys.push_back("Citrix.ICAClient.2.4");
  HKCR_Keys.push_back("Citrix.ICAClient.2.5");
  HKCR_Keys.push_back("Citrix.ICAClient.2.6");
  HKCR_Keys.push_back("Citrix.ICAClient.2.7");
  HKCR_Keys.push_back("Citrix.ICAClient.2.8");
  HKCR_Keys.push_back("Citrix.ICAClient.2.9");
  HKCR_Keys.push_back("Citrix.ICAClientProp");
  HKCR_Keys.push_back("Citrix.ICAClientProp.2");
  HKCR_Keys.push_back("Citrix.ICAClientProp.2.1");
  HKCR_Keys.push_back("Citrix.ICAClientProp.2.2");
  HKCR_Keys.push_back("Citrix.ICAClientProp.2.3");
  HKCR_Keys.push_back("Citrix.ICAClientProp.2.4");
  HKCR_Keys.push_back("CLSID\\{0BB94541-4EB9-4134-B201-E1E33B78DEE6}");
  HKCR_Keys.push_back("CLSID\\{0C8FDBDF-A229-48c0-9961-5248F0341C78}");
  HKCR_Keys.push_back("CLSID\\{0D0BFABF-6E29-4325-9822-BFE12A1221F8}");
  HKCR_Keys.push_back("CLSID\\{1EFF7739-9BDA-4295-BC07-383554CAAC84}");
  HKCR_Keys.push_back("CLSID\\{238F6F83-B8B4-11CF-8771-00A024541EE3}");
  HKCR_Keys.push_back("CLSID\\{238F6F85-B8B4-11CF-8771-00A024541EE3}");
  HKCR_Keys.push_back("CLSID\\{2C4631FF-5CC8-4EBC-A0DF-34C92291759E}");
  HKCR_Keys.push_back("CLSID\\{5FE65B49-6E43-4F1E-A1BB-AC6552EC96AE}");
  HKCR_Keys.push_back("CLSID\\{6735160D-E201-4e53-A673-D56B2CF1D1A2}");
  HKCR_Keys.push_back("CLSID\\{86E3101B-A2D5-4EEE-83C6-38621B4C8219}");
  HKCR_Keys.push_back("CLSID\\{9EF5EF7A-DB82-464A-ACD0-1BC9416E3268}");
  HKCR_Keys.push_back("CLSID\\{BDE6DF17-29A7-4471-AC7D-638B9E7D6F37}");
  HKCR_Keys.push_back("CLSID\\{C50DD3BE-D578-4BD6-AB5E-C7B4DC1D1F49}");
  HKCR_Keys.push_back("CLSID\\{CFB6322E-CC85-4d1b-82C7-893888A236BC}");
  HKCR_Keys.push_back("CLSID\\{D085A4AB-CAB1-4729-9DF8-FCEEDDBD19E4}");
  HKCR_Keys.push_back("CLSID\\{D24686A9-95D7-4209-BC78-A907BC9B5CC8}");
  HKCR_Keys.push_back("CLSID\\{E57471C6-CC72-4E5C-B446-1DCFC9D85341}");
  HKCR_Keys.push_back("CLSID\\{E61FEC89-CFBB-43A1-AC1D-4656D3714F4F}");
  HKCR_Keys.push_back("cr.Document");
  HKCR_Keys.push_back("IEInterceptor.InterceptorBHO");
  HKCR_Keys.push_back("IEInterceptor.InterceptorBHO.1");
  HKCR_Keys.push_back("Installer\\Assemblies\\C:|Program Files|Citrix|ICA Client|XPSPrintHelper.exe");
  HKCR_Keys.push_back("Installer\\Products\\32782E4C36602104B9CD2EA1411C13C6");
  HKCR_Keys.push_back("Installer\\Products\\34B5C1E0738189F49AB6978A0A5A59F5");
  HKCR_Keys.push_back("Installer\\Products\\358CA8E5BB5699C40AE9918B81151EC4");
  HKCR_Keys.push_back("Installer\\Products\\A063EE9D91C7CE74397C79EDFF4608B4");
  HKCR_Keys.push_back("Installer\\Products\\D38A8EDA07BB5BF4AB91624CE73A8149");
  HKCR_Keys.push_back("Installer\\Products\\D50055ACCA496954696476D9C60C6D02");
  HKCR_Keys.push_back("Installer\\Products\\FC95C210A470AD3408586B6E6337B395");
  HKCR_Keys.push_back("Installer\\Products\\DC3BF90CC0D3D2F398A9A6D1762F70F3");
  HKCR_Keys.push_back("Installer\\Products\\ACF7117400D0D6B4D986007B36264936");
  HKCR_Keys.push_back("MIME\\Database\\Content Type\\application/vnd.citrix.receiver.configure");
  HKCR_Keys.push_back("TypeLib\\{238F6F80-B8B4-11CF-8771-00A024541EE3}");
  HKCR_Keys.push_back("TypeLib\\{2D646468-6FEC-408C-B7CF-FB258D2AA0EB}");
  HKCR_Keys.push_back("TypeLib\\{3D3FCA3F-FA3F-4ACB-A793-DF6FFACC991A}");
  HKCR_Keys.push_back("TypeLib\\{6242C275-4165-41C3-B283-A41EEEDB06D1}");
  HKCR_Keys.push_back("TypeLib\\{919B1DD4-91CE-455A-9CB3-437BFE502117}");
  HKCR_Keys.push_back("TypeLib\\{A2E3CD1C-C98A-4F62-9F6B-CA40E8E5CA34}");
  HKCR_Keys.push_back("TypeLib\\{A8C50DA6-6948-4D52-977F-C156A441E365}");
  HKCR_Keys.push_back("WinFrameICA");
  
  HKLM_Keys.push_back("SOFTWARE\\Citrix");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\.cr");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\.ica");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.AuthManager");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.AuthManager.5");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.AuthSingleUseFactory");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.AuthSingleUseFactory.4");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClient");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClient.2.1");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClient.2.2");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClient.2.3");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClient.2.4");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClient.2.5");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClient.2.6");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClient.2.7");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClient.2.8");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClient.2.9");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClientProp");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClientProp.2");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClientProp.2.1");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClientProp.2.2");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClientProp.2.3");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Citrix.ICAClientProp.2.4");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{0BB94541-4EB9-4134-B201-E1E33B78DEE6}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{0C8FDBDF-A229-48c0-9961-5248F0341C78}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{0D0BFABF-6E29-4325-9822-BFE12A1221F8}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{1EFF7739-9BDA-4295-BC07-383554CAAC84}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{238F6F83-B8B4-11CF-8771-00A024541EE3}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{238F6F85-B8B4-11CF-8771-00A024541EE3}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{2C4631FF-5CC8-4EBC-A0DF-34C92291759E}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{5FE65B49-6E43-4F1E-A1BB-AC6552EC96AE}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{6735160D-E201-4e53-A673-D56B2CF1D1A2}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{86E3101B-A2D5-4EEE-83C6-38621B4C8219}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{9EF5EF7A-DB82-464A-ACD0-1BC9416E3268}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{BDE6DF17-29A7-4471-AC7D-638B9E7D6F37}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{C50DD3BE-D578-4BD6-AB5E-C7B4DC1D1F49}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{CFB6322E-CC85-4d1b-82C7-893888A236BC}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{D085A4AB-CAB1-4729-9DF8-FCEEDDBD19E4}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{D24686A9-95D7-4209-BC78-A907BC9B5CC8}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{E57471C6-CC72-4E5C-B446-1DCFC9D85341}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\CLSID\\{E61FEC89-CFBB-43A1-AC1D-4656D3714F4F}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\cr.Document");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\IEInterceptor.InterceptorBHO");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\IEInterceptor.InterceptorBHO.1");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Installer\\Assemblies\\C:|Program Files|Citrix|ICA Client|XPSPrintHelper.exe");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Installer\\Products\\32782E4C36602104B9CD2EA1411C13C6");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Installer\\Products\\34B5C1E0738189F49AB6978A0A5A59F5");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Installer\\Products\\358CA8E5BB5699C40AE9918B81151EC4");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Installer\\Products\\A063EE9D91C7CE74397C79EDFF4608B4");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Installer\\Products\\D38A8EDA07BB5BF4AB91624CE73A8149");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Installer\\Products\\D50055ACCA496954696476D9C60C6D02");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Installer\\Products\\FC95C210A470AD3408586B6E6337B395");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Installer\\Products\\DC3BF90CC0D3D2F398A9A6D1762F70F3");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\Installer\\Products\\ACF7117400D0D6B4D986007B36264936");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\MIME\\Database\\Content Type\\application/vnd.citrix.receiver.configure");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\TypeLib\\{238F6F80-B8B4-11CF-8771-00A024541EE3}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\TypeLib\\{2D646468-6FEC-408C-B7CF-FB258D2AA0EB}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\TypeLib\\{3D3FCA3F-FA3F-4ACB-A793-DF6FFACC991A}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\TypeLib\\{6242C275-4165-41C3-B283-A41EEEDB06D1}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\TypeLib\\{919B1DD4-91CE-455A-9CB3-437BFE502117}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\TypeLib\\{A2E3CD1C-C98A-4F62-9F6B-CA40E8E5CA34}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\TypeLib\\{A8C50DA6-6948-4D52-977F-C156A441E365}");
  HKLM_Keys.push_back("SOFTWARE\\Classes\\WinFrameICA");
  HKLM_Keys.push_back("SOFTWARE\\Microsoft\\Internet Explorer\\Extension Compatibility\\{238F6F83-B8B4-11CF-8771-00A024541EE3}");
  HKLM_Keys.push_back("SOFTWARE\\Microsoft\\Internet Explorer\\Low Rights\\ElevationPolicy\\{872D2695-45ED-4B48-8996-15FADA38E288}");
  HKLM_Keys.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\CitrixReciver");
  HKLM_Keys.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ConnectionCenter");
  HKLM_Keys.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Redirector");
  HKLM_Keys.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{012C59CF-074A-43DA-8085-B6E636733B59}");
  HKLM_Keys.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{0E1C5B43-1837-4F98-A96B-79A8A0A5955F}");
  HKLM_Keys.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{47117FCA-0D00-4B6D-9D68-00B763629463}");
  HKLM_Keys.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{5E8AC853-65BB-4C99-A09E-19B81851E14C}");
  HKLM_Keys.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{ADE8A83D-BB70-4FB5-BA19-26C47EA31894}");
  HKLM_Keys.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{C4E28723-0663-4012-9BDC-E21A14C1316C}");
  HKLM_Keys.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{CA55005D-94AC-4596-9646-679D6CC0D620}");
  HKLM_Keys.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{D9EE360A-7C19-47EC-93C7-97DEFF64804B}");
  HKLM_Keys.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{F390D923-76F1-458E-8218-8C0C156CDCFD}");
  HKLM_Keys.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\CitrixOnlinePluginPackWeb");
  HKLM_Keys.push_back("SOFTWARE\\MozillaPlugins\\@Citrix.com/npican");
}

bool RegDelNodeRecurse(HKEY hKeyRoot, LPSTR lpSubKey)
{
  LPSTR lpEnd;
  LONG lResult;
  DWORD dwSize;
  char szName[MAX_PATH];
  HKEY hKey;
  FILETIME ftWrite;
  
  lResult = RegDeleteKey(hKeyRoot, lpSubKey);
  if(lResult == ERROR_SUCCESS)
  {
    cout<<"["<<lpSubKey<<"] Key deleted"<<endl;;
    return true;
  }
  
  lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);
  if(lResult != ERROR_SUCCESS)
  {
    cout<<"["<<lpSubKey<<"] ";
    if(lResult == ERROR_FILE_NOT_FOUND)
    {
      cout<<"Key not found"<<endl;
      return true;
    }
    else
    {
      cout<<"Error opening key"<<endl;
      return false;
    }
  }
  
  lpEnd = lpSubKey + lstrlen(lpSubKey);
  if(*(lpEnd-1) != '\\')
  {
    *lpEnd = '\\';
    lpEnd++;
    *lpEnd = '\0';
  }
  
  dwSize = MAX_PATH;
  lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL, NULL, NULL, &ftWrite);
  if(lResult == ERROR_SUCCESS)
  {
    do
    {
      strcpy(lpEnd, szName);
      if(!RegDelNodeRecurse(hKeyRoot, lpSubKey))
      {
        break;
      }
      dwSize = MAX_PATH;
      lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL, NULL, NULL, &ftWrite);
    }
    while(lResult == ERROR_SUCCESS);
  }
  lpEnd --;
  *lpEnd = '\0';
  RegCloseKey(hKey);
  lResult = RegDeleteKey(hKeyRoot, lpSubKey);
  if(lResult == ERROR_SUCCESS) return true;
  
  return false;
}

bool RegDelNode(HKEY hKeyRoot, LPSTR lpSubKey)
{
  char szDelKey[MAX_PATH*2];
  strcpy(szDelKey, lpSubKey);
  return RegDelNodeRecurse(hKeyRoot, szDelKey);
}

bool DeleteCitrixKeys(bool StdKeys = true)
{
  if(StdKeys)
  {
    cout<<"Generate registry key list ..."<<endl;
    CreateKeysList();
    //HKCR
    cout<<"Deleting HKCR_Keys ..."<<endl;
    for(int i=0; i<HKCR_Keys.size(); i++)
    {
      RegDelNode(HKEY_CLASSES_ROOT, (char*)HKCR_Keys[i].c_str());
    }
    //HKLM
    cout<<"Deleting HKLM_Keys ..."<<endl;
    for(int i=0; i<HKLM_Keys.size(); i++)
    {
      RegDelNode(HKEY_LOCAL_MACHINE, (char*)HKLM_Keys[i].c_str());
    }
  }  
  return true;
}

bool TryEndProcess(PROCESSENTRY32 &entry, char *ExeName)
{
  if(stricmp(entry.szExeFile, ExeName) != 0) return false;
  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
  if(!hProcess) return false;
  if(!TerminateProcess(hProcess, 0)) return false;
  //cout<<"Process ["<<ExeName<<"] terminated"<<endl;
  //else cout<<"Process ["<<ExeName<<"] NOT terminated"<<endl;
  CloseHandle(hProcess);
  return true;   
}

bool DeleteCitrixProcesses()
{
  PROCESSENTRY32 entry;
  entry.dwSize = sizeof(PROCESSENTRY32);
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
  cout<<"Trying to kill Citrix processes: "<<endl;
  cout<<"concentr.exe"<<endl;
  cout<<"wfcrun32.exe"<<endl;
  cout<<"redirector.exe"<<endl;
  cout<<"SelfServicePlugin.exe"<<endl;
  cout<<"Receiver.exe"<<endl;
  if(Process32First(snapshot, &entry) == TRUE)
  {
    while(Process32Next(snapshot, &entry) == TRUE)
    {
      if(TryEndProcess(entry, CONCENTR)) cout<<CONCENTR<<" terminated"<<endl;
      if(TryEndProcess(entry, WFCRUN)) cout<<WFCRUN<<" terminated"<<endl;
      if(TryEndProcess(entry, REDIR)) cout<<REDIR<<" terminated"<<endl;
      if(TryEndProcess(entry, SELFSER)) cout<<SELFSER<<" terminated"<<endl;
      if(TryEndProcess(entry, RECEIVER)) cout<<RECEIVER<<" terminated"<<endl;
    }
  }
  CloseHandle(snapshot);
}

int DeleteDirectory(const std::string &refcstrRootDirectory, bool bDeleteSubdirectories = true)
{
  bool            bSubdirectory = false;       // Flag, indicating whether
                                               // subdirectories have been found
  HANDLE          hFile;                       // Handle to directory
  std::string     strFilePath;                 // Filepath
  std::string     strPattern;                  // Pattern
  WIN32_FIND_DATA FileInformation;             // File information


  strPattern = refcstrRootDirectory + "\\*.*";
  hFile = ::FindFirstFile(strPattern.c_str(), &FileInformation);
  if(hFile != INVALID_HANDLE_VALUE)
  {
    do
    {
      if(FileInformation.cFileName[0] != '.')
      {
        strFilePath.erase();
        strFilePath = refcstrRootDirectory + "\\" + FileInformation.cFileName;

        if(FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
          if(bDeleteSubdirectories)
          {
            // Delete subdirectory
            int iRC = DeleteDirectory(strFilePath, bDeleteSubdirectories);
            if(iRC)
              return iRC;
          }
          else
            bSubdirectory = true;
        }
        else
        {
          // Set file attributes
          if(::SetFileAttributes(strFilePath.c_str(),
                                 FILE_ATTRIBUTE_NORMAL) == FALSE)
            return ::GetLastError();

          // Delete file
          if(::DeleteFile(strFilePath.c_str()) == FALSE)
            return ::GetLastError();
        }
      }
    } while(::FindNextFile(hFile, &FileInformation) == TRUE);

    // Close handle
    ::FindClose(hFile);

    DWORD dwError = ::GetLastError();
    if(dwError != ERROR_NO_MORE_FILES)
      return dwError;
    else
    {
      if(!bSubdirectory)
      {
        // Set directory attributes
        if(::SetFileAttributes(refcstrRootDirectory.c_str(),
                               FILE_ATTRIBUTE_NORMAL) == FALSE)
          return ::GetLastError();

        // Delete directory
        if(::RemoveDirectory(refcstrRootDirectory.c_str()) == FALSE)
          return ::GetLastError();
      }
    }
  }
  return 0;
}

bool DeleteCitixDirectory()
{
  DeleteDirectory(MAINDIR);
  DeleteDirectory(COMMON);
  return true;
}

int main(int argc, char *argv[])
{
    char Press;
    cout<<"You really want to delete all citrix data (y/n)? ";
    cin>>Press;
    switch(Press)
    {
      case 'y':
        cout<<"Terminating processes ..."<<endl;
        DeleteCitrixProcesses();
        cout<<"Deleting reg keys ..."<<endl;
        DeleteCitrixKeys();
        cout<<"Deleting directorys ..."<<endl;
        DeleteCitixDirectory();
        break;
      case 'n':
        cout<<"Select operation to do"<<endl<<"1 - kill processes, 2 - delete reg keys, 3 - delete directory, 0 - exit"<<endl;
        cin>>Press;
        switch(Press)
        {
          case '1':
            DeleteCitrixProcesses();   
            break;
          case '2':
            DeleteCitrixKeys();
            break;
          case '3':
            DeleteCitixDirectory();
            break;
        }
        break;
      default:
        break;
    }
    cout<<"Bye"<<endl;
    cin.get();
    system("PAUSE");
    return EXIT_SUCCESS;
}
