//          Copyright Maarten L. Hekkelman 2006-2008
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include "MWinLib.h"

#include <wincrypt.h>
#include <Aclapi.h>

#include <cryptopp/base64.h>

#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH

#include "..\Ssh\MSsh.h"
#include "..\Ssh\MSshPacket.h"
#include "..\Ssh\MSshAgent.h"
#include "..\Ssh\MSshAgentImpl.h"
#include "MWinApplicationImpl.h"
#include "MPreferences.h"
#include "MWinUtils.h"

#pragma comment (lib, "crypt32")

#include <wincrypt.h>

using namespace CryptoPP;
using namespace std;

// --------------------------------------------------------------------
// We support Pageant compatible signing.

const wchar_t kPageantName[] = L"Pageant";
const uint32 AGENT_COPYDATA_ID = 0x804e50ba;   /* random goop */

class MCertificateStore
{
  public:
	
	static MCertificateStore&	Instance();
	
				operator HCERTSTORE ()			{ return mCertificateStore; }

  private:
				MCertificateStore();
				~MCertificateStore();

	void		Check();

	static LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
	static void CALLBACK Timer(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime);

	HCERTSTORE	mCertificateStore;
	HWND		mPageant;
	HANDLE		mEvent;
};

MCertificateStore::MCertificateStore()
	: mPageant(nullptr)
	, mCertificateStore(::CertOpenSystemStoreW(0, L"MY"))
	, mEvent(::CreateEvent(nullptr, false, false, nullptr))
{
	::CertControlStore(mCertificateStore, 0, CERT_STORE_CTRL_NOTIFY_CHANGE, &mEvent);
	::SetTimer(nullptr, 0, 1000, &MCertificateStore::Timer);
	
	if (Preferences::GetBoolean("act-as-pageant", true))
	{
		try
		{
			HINSTANCE inst = MWinApplicationImpl::GetInstance()->GetHInstance();
	
			WNDCLASS lWndClass = { sizeof(WNDCLASS) };
			lWndClass.lpszClassName = kPageantName;
	
			if (not ::GetClassInfo(inst, lWndClass.lpszClassName, &lWndClass))
			{
				lWndClass.lpfnWndProc = &MCertificateStore::WndProc;
				lWndClass.hInstance = inst;
				::RegisterClass(&lWndClass);
			}
	
			mPageant = ::CreateWindow(kPageantName, kPageantName,
					0, 0, 0, 0, 0, HWND_MESSAGE, NULL, inst, NULL);
		}
		catch (...)
		{
			mPageant = nullptr;
		}
	}
}

MCertificateStore::~MCertificateStore()
{
	if (mEvent != nullptr)
		::CloseHandle(mEvent);

	if (mCertificateStore != nullptr)
	{
		if (not ::CertCloseStore(mCertificateStore, CERT_CLOSE_STORE_CHECK_FLAG) and ::GetLastError() == CRYPT_E_PENDING_CLOSE)
			PRINT(("crypt pending close"));
	}
}

void MCertificateStore::Check()
{
	if (::WaitForSingleObjectEx(mEvent, 0, false) == WAIT_OBJECT_0)
	{
		::CertControlStore(mCertificateStore, 0, CERT_STORE_CTRL_RESYNC, &mEvent);

		MSshAgent::Instance().Update();
	}
}

MCertificateStore& MCertificateStore::Instance()
{
	static MCertificateStore sInstance;
	return sInstance;
}

LRESULT CALLBACK MCertificateStore::WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	LRESULT result = 0;
	
	try
	{
		switch (message)
		{
			case WM_COPYDATA:
			{
				uint8* p = nullptr;
				HANDLE mapFile = nullptr;
				
				do
				{
					COPYDATASTRUCT *cds = reinterpret_cast<COPYDATASTRUCT*>(lParam);
					if (cds == nullptr or cds->dwData != AGENT_COPYDATA_ID)
						break;
					
					char* fileName = reinterpret_cast<char*>(cds->lpData);
					if (fileName == nullptr or fileName[cds->cbData - 1] != 0)
						break;
					
					mapFile = ::OpenFileMappingA(FILE_MAP_ALL_ACCESS, false,
						fileName);
					if (mapFile == nullptr or mapFile == INVALID_HANDLE_VALUE)
						break;
					
					p = reinterpret_cast<uint8*>(::MapViewOfFile(mapFile, FILE_MAP_WRITE, 0, 0, 0));
					if (p == nullptr)
						break;
					
					HANDLE proc = ::OpenProcess(MAXIMUM_ALLOWED, false, ::GetCurrentProcessId());
					if (proc == nullptr)
						break;
					
					PSECURITY_DESCRIPTOR procSD = nullptr, mapSD = nullptr;
					PSID mapOwner, procOwner;
					
					if (::GetSecurityInfo(proc, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
							&procOwner, nullptr, nullptr, nullptr, &procSD) != ERROR_SUCCESS)
					{
						if (procSD != nullptr)
							::LocalFree(procSD);
						procSD = nullptr;
					}
					::CloseHandle(proc);
					
					if (::GetSecurityInfo(mapFile, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
						&mapOwner, nullptr, nullptr, nullptr, &mapSD) != ERROR_SUCCESS)
					{
						if (mapSD != nullptr)
							::LocalFree(mapSD);
						mapSD = nullptr;
					}
					
					if (::EqualSid(mapOwner, procOwner))
					{
						uint32 len = p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
						if (len < 10240)
						{
							MSshPacket in(p + 4, len);
							MSshPacket out;
							
							MSshAgent::Instance().ProcessAgentRequest(in, out);
							
							MSshPacket wrapped;
							wrapped << out;
	
							copy(wrapped.peek(), wrapped.peek() + wrapped.size(), p);
							result = 1;
						}
					}
					
					if (procSD != nullptr)
						::LocalFree(procSD);
					
					if (mapSD != nullptr)
						::LocalFree(mapSD);
				}
				while (false);

				if (p != nullptr)
					::UnmapViewOfFile(p);
				
				if (mapFile != nullptr and mapFile != INVALID_HANDLE_VALUE)
					::CloseHandle(mapFile);

				break;
			}

			default:
				result = ::DefWindowProc(hwnd, message, wParam, lParam);
				break;
		}
	}
	catch (...)
	{
	}
	
	return result;
}

void MCertificateStore::Timer(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
	MCertificateStore::Instance().Check();
}

// --------------------------------------------------------------------

class MWinSshPrivateKeyImpl : public MSshPrivateKeyImpl
{
  public:
  					MWinSshPrivateKeyImpl(PCCERT_CONTEXT inCertificateContext);
	virtual			~MWinSshPrivateKeyImpl();

	virtual void	SignData(const MSshPacket& inData,
						vector<uint8>& outSignature);

	virtual string	GetHash() const;
	virtual string	GetComment() const;

  private:
	PCCERT_CONTEXT	mCertificateContext;
};

MWinSshPrivateKeyImpl::MWinSshPrivateKeyImpl(PCCERT_CONTEXT inCertificateContext)
	: mCertificateContext(inCertificateContext)
{
	DWORD cbPublicKeyStruc = 0;
	PCERT_PUBLIC_KEY_INFO pk = &mCertificateContext->pCertInfo->SubjectPublicKeyInfo;
	
	if (::CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		RSA_CSP_PUBLICKEYBLOB, pk->PublicKey.pbData, pk->PublicKey.cbData,
	    0, nullptr, &cbPublicKeyStruc))
	{
		vector<uint8> b(cbPublicKeyStruc);
		
		if (::CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			RSA_CSP_PUBLICKEYBLOB, pk->PublicKey.pbData, pk->PublicKey.cbData,
		    0, &b[0], &cbPublicKeyStruc))
		{
			PUBLICKEYSTRUC* pks = reinterpret_cast<PUBLICKEYSTRUC*>(&b[0]);
			
			if ((pks->aiKeyAlg & ALG_TYPE_RSA) == 0)
				THROW(("Not an RSA signing key"));

			RSAPUBKEY* pkd = reinterpret_cast<RSAPUBKEY*>(&b[0] + sizeof(PUBLICKEYSTRUC));
			byte* data = reinterpret_cast<byte*>(&b[0] + sizeof(RSAPUBKEY) + sizeof(PUBLICKEYSTRUC));
			
			mE = pkd->pubexp;
			
			// public key is in little endian format
			uint32 len = pkd->bitlen / 8;
			
			reverse(data, data + len);
			mN = Integer(data, len);
		}
	}
}

MWinSshPrivateKeyImpl::~MWinSshPrivateKeyImpl()
{
	if (mCertificateContext != nullptr)
		::CertFreeCertificateContext(mCertificateContext);
}

void MWinSshPrivateKeyImpl::SignData(
	const MSshPacket& inData, vector<uint8>& outSignature)
{
	BOOL freeKey = false;
	DWORD keySpec, cb;
	HCRYPTPROV key;
	
	if (::CryptAcquireCertificatePrivateKey(mCertificateContext, 0, nullptr, &key, &keySpec, &freeKey))
	{
		HCRYPTHASH hash;

		if (::CryptCreateHash(key, CALG_SHA1, 0, 0, &hash))
		{
			if (::CryptHashData(hash, inData.peek(), inData.size(), 0))
			{
				cb = 0;
				::CryptSignHash(hash, keySpec, nullptr, 0, nullptr, &cb);
				
				if (cb > 0)
				{
					vector<uint8> b(cb);
					if (::CryptSignHash(hash, keySpec, nullptr, 0, &b[0], &cb))
					{
						// data is in little endian format
						reverse(&b[0], &b[0] + cb);
						swap(outSignature, b);
					}
				}
			}
			
			::CryptDestroyHash(hash);
		}
		
		if (freeKey)
			::CryptReleaseContext(key, 0);
	}
}

string MWinSshPrivateKeyImpl::GetComment() const
{
	string comment;

	// now we have a public key, try to fetch a comment as well
	DWORD types[] = { CERT_NAME_UPN_TYPE, CERT_NAME_FRIENDLY_DISPLAY_TYPE,
		CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_EMAIL_TYPE, CERT_NAME_ATTR_TYPE };

	foreach (DWORD type, types)
	{
		DWORD cb = ::CertGetNameString(mCertificateContext, type,
			CERT_NAME_DISABLE_IE4_UTF8_FLAG, nullptr, nullptr, 0);
		if (cb > 1)
		{
			vector<wchar_t> b(cb);
			::CertGetNameString(mCertificateContext, type,
				CERT_NAME_DISABLE_IE4_UTF8_FLAG, nullptr, &b[0], cb);
			comment = w2c(&b[0]);

			if (not comment.empty())
				break;
		}
	}

	return comment;
}

string MWinSshPrivateKeyImpl::GetHash() const
{
	string hash;

	// and create a hash for this key
	byte sha1[20];	// SHA1 hash is always 20 bytes
	DWORD cbHash = sizeof(sha1);
			
	if (::CertGetCertificateContextProperty(mCertificateContext,
		CERT_HASH_PROP_ID, sha1, &cbHash))
	{
		Base64Encoder enc(new StringSink(hash));
		enc.Put(sha1, cbHash);
		enc.MessageEnd(true);
	}

	return hash;
}

// --------------------------------------------------------------------

MSshPrivateKeyImpl*	MSshPrivateKeyImpl::CreateForHash(const std::string& inHash)
{
	string hash;

	Base64Decoder d(new StringSink(hash));
	d.Put(reinterpret_cast<const byte*>(inHash.c_str()), inHash.length());
	d.MessageEnd();
	
	CRYPT_HASH_BLOB k;
	k.cbData = hash.length();
	k.pbData = const_cast<byte*>(reinterpret_cast<const byte*>(hash.c_str()));
	
	PCCERT_CONTEXT context = ::CertFindCertificateInStore(
		MCertificateStore::Instance(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		0, CERT_FIND_SHA1_HASH, &k, nullptr);
	
	if (context == nullptr)
		THROW(("Certificate not found"));

	return new MWinSshPrivateKeyImpl(context);
}

MSshPrivateKeyImpl*	MSshPrivateKeyImpl::CreateForBlob(MSshPacket& inBlob)
{
	MSshPrivateKeyImpl* result = nullptr;
	
	PCCERT_CONTEXT context = ::CertEnumCertificatesInStore(
		MCertificateStore::Instance(), nullptr);
	
	while (context != nullptr)
	{
		try
		{
			result = new MWinSshPrivateKeyImpl(::CertDuplicateCertificateContext(context));
			result->Reference();

			MSshPrivateKey key(result);
		
			MSshPacket blob;
			blob << key;
			
			if (blob == inBlob)
			{
				::CertFreeCertificateContext(context);
				break;
			}
			
			result->Release();
			result = nullptr;
		}
		catch (...) {}

		context = ::CertEnumCertificatesInStore(MCertificateStore::Instance(), context);
	}
	
	return result;
}

void MSshPrivateKeyImpl::CreateList(vector<MSshPrivateKey>& outKeys)
{
	PCCERT_CONTEXT context = ::CertEnumCertificatesInStore(
		MCertificateStore::Instance(), nullptr);
	
	while (context != nullptr)
	{
		outKeys.push_back(
			MSshPrivateKey(new MWinSshPrivateKeyImpl(::CertDuplicateCertificateContext(context))));
		context = ::CertEnumCertificatesInStore(MCertificateStore::Instance(), context);
	}
}
