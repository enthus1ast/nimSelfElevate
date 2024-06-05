## Code to UAC elevate a process 
## copied from there:
##  http://forum.nim-lang.org/t/1641

import winim
import strformat, os, strutils

type
  TOKEN_ELEVATION {.final, pure.} = object
    TokenIsElevated*: DWORD
  
  TOK_INFO_CLASS {.pure.} = enum
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId,
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert,
    TokenAuditPolicy,
    TokenOrigin,
    TokenElevationType,
    TokenLinkedToken,
    TokenElevation,
    TokenHasRestrictions,
    TokenAccessInformation,
    TokenVirtualizationAllowed,
    TokenVirtualizationEnabled,
    TokenIntegrityLevel,
    TokenUIAccess,
    TokenMandatoryPolicy,
    TokenLogonSid,
    TokenIsAppContainer,
    TokenCapabilities,
    TokenAppContainerSid,
    TokenAppContainerNumber,
    TokenUserClaimAttributes,
    TokenDeviceClaimAttributes,
    TokenRestrictedUserClaimAttributes,
    TokenRestrictedDeviceClaimAttributes,
    TokenDeviceGroups,
    TokenRestrictedDeviceGroups,
    TokenSecurityAttributes,
    TokenIsRestricted,
    MaxTokenInfoClass


proc GetTokenInformation(TokenHandle: HANDLE;
                          TokenInformationClass: TOK_INFO_CLASS;
                          TokenInformation: LPVOID;
                          TokenInformationLength: DWORD; ReturnLength: PDWORD): WINBOOL {.
    stdcall, dynlib: "advapi32", importc: "GetTokenInformation".}


proc isUserElevated*(): bool =
  var
    tokenHandle: HANDLE
    elevation = TOKEN_ELEVATION()
    cbsize: DWORD = 0
  
  if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, cast[PHANDLE](addr(tokenHandle))) == 0:
    raise newException(Exception, fmt"Cannot query tokens ({GetLasterror()})")
  
  if GetTokenInformation(tokenHandle, TOK_INFO_CLASS.TokenElevation, cast[LPVOID](addr(elevation)), cast[DWORD](sizeOf(elevation)), cast[PDWORD](addr(cbsize))) == 0:
    let lastError = GetLastError()
    discard CloseHandle(tokenHandle)
    raise newException(Exception, fmt"Cannot retrieve token information ({lastError})")
  
  result = elevation.TokenIsElevated != 0


proc elevateWin*(path: string = getAppFilename()) =
  var
    pathToExe: WideCString
    verb = newWideCString("runas")
    params: WideCString
  
  pathToExe = newWideCString(path)
  params = newWideCString(commandLineParams().join(" "))
  
  var lastError = ShellExecuteW(0, cast[LPWSTR](addr verb[0]), cast[LPWSTR](addr pathToExe[0]), cast[LPWSTR](addr params[0]), cast[LPWSTR](0), SW_SHOWNORMAL)
  if lastError <= 32:
    raise newException(Exception, fmt"Cannot elevate {pathToExe} (lastError)")


# proc elevateOrExit*() =
#   tries = tries + 1
#   if tries == maxTries:
#     echo "reached the max tries for elevating...."
#     quit(0) # we have reached 
#   if not isUserElevated():
#     elevateWin()
#     echo "Now elevating!"
#     quit(0)
#   else:
#     echo "Already elevated!"  

when isMainModule:
  echo "Start"
  if not isUserElevated():
    elevateWin()
    echo "Now elevating!"
  else:
    echo "Already elevated!"
    var line: TaintedString = ""
    discard stdin.readLine(line)
