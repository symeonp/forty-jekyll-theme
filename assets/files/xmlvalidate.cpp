#include "stdafx.h"
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <objbase.h>  
#include <msxml6.h>  
#include <comdef.h>
#import <msxml6.dll>

// Macro that calls a COM method returning HRESULT value.
#define CHK_HR(stmt)        do { hr=(stmt); if (FAILED(hr)) goto CleanUp; } while(0)

using namespace MSXML2;
extern "C" __declspec(dllexport) _bstr_t fuzzme(wchar_t* filename);
extern "C" __declspec(dllexport)  int main(int argc, char** argv);

void dump_com_error(_com_error &e)
{
    _bstr_t bstrSource(e.Source());
    _bstr_t bstrDescription(e.Description());

    printf("Error\n");
    printf("\a\tCode = %08lx\n", e.Error());
    printf("\a\tCode meaning = %s", e.ErrorMessage());
    printf("\a\tSource = %s\n", (LPCSTR)bstrSource);
    printf("\a\tDescription = %s\n", (LPCSTR)bstrDescription);
}

_bstr_t validateFile(_bstr_t bstrFile)
{
    // Initialize objects and variables.
    MSXML2::IXMLDOMDocument2Ptr pXMLDoc;
    MSXML2::IXMLDOMParseErrorPtr pError;
    _bstr_t bstrResult = L"";
    HRESULT hr = S_OK;

    // Create a DOMDocument and set its properties.
    CHK_HR(pXMLDoc.CreateInstance(__uuidof(MSXML2::DOMDocument60), NULL, CLSCTX_INPROC_SERVER));

    pXMLDoc->async = VARIANT_FALSE;
    pXMLDoc->validateOnParse = VARIANT_TRUE;
    pXMLDoc->resolveExternals = VARIANT_TRUE;

    // Load and validate the specified file into the DOM.
    // And return validation results in message to the user.
    if (pXMLDoc->load(bstrFile) != VARIANT_TRUE)
    {
        pError = pXMLDoc->parseError;

        bstrResult = _bstr_t(L"Validation failed on ") + bstrFile +
            _bstr_t(L"\n=====================") +
            _bstr_t(L"\nReason: ") + _bstr_t(pError->Getreason()) +
            _bstr_t(L"\nSource: ") + _bstr_t(pError->GetsrcText()) +
            _bstr_t(L"\nLine: ") + _bstr_t(pError->Getline()) +
            _bstr_t(L"\n");
        printf("\n[-] Validation failed: %s", _bstr_t(pError->Getreason()));

    }
    else
    {
        bstrResult = _bstr_t(L"Validation succeeded for ") + bstrFile +
            _bstr_t(L"\n======================\n") +
            _bstr_t(pXMLDoc->xml) + _bstr_t(L"\n");
        printf("\n[+] Validation succeeded");

    }

CleanUp:
    return bstrResult;
}

wchar_t* charToWChar(const char* text)
{
    size_t size = strlen(text) + 1;
    wchar_t* wa = new wchar_t[size];
    mbstowcs(wa, text, size);
    return wa;
}

_bstr_t fuzzme(wchar_t* filename)
{
    _bstr_t bstrOutput = validateFile(filename);
    //bstrOutput += validateFile(L"nn-notValid.xml");
    //MessageBoxW(NULL, bstrOutput, L"noNamespace", MB_OK);
    return bstrOutput;

}
int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("Usage: %s <xml file>\n", argv[0]);
        return 0;
    }

    HRESULT hr = CoInitialize(NULL);
    if (SUCCEEDED(hr))
    {
        try
        {
            _bstr_t bstrOutput = fuzzme(charToWChar(argv[1]));
        }
        catch (_com_error &e)
        {
            dump_com_error(e);
        }
        CoUninitialize();
    }
    return 0;
}