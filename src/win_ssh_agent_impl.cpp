//          Copyright Maarten L. Hekkelman 2006-2008
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <assh/ssh_agent.hpp>
#include <assh/detail/ssh_agent_impl.hpp>
#include <assh/packet.hpp>

#include <winsdkver.h>
#include <Aclapi.h>
#include <wincrypt.h>

#include <cryptopp/base64.h>

#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH


#pragma comment (lib, "crypt32")

using namespace CryptoPP;
using namespace std;

namespace assh
{

// --------------------------------------------------------------------
// We support Pageant compatible signing.

const wchar_t kPageantName[] = L"Pageant";
const uint32 AGENT_COPYDATA_ID = 0x804e50ba;   /* random goop */

class MCertificateStore
{
  public:
	
	static MCertificateStore&	Instance();
	
				operator HCERTSTORE ()			{ return mCertificateStore; }

	bool		GetPublicKey(PCCERT_CONTEXT context, Integer& e, Integer& n);

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
	
	//if (Preferences::GetBoolean("act-as-pageant", true))
	//{
	//	try
	//	{
	//		HINSTANCE inst = MWinApplicationImpl::GetInstance()->GetHInstance();
	//
	//		WNDCLASS lWndClass = { sizeof(WNDCLASS) };
	//		lWndClass.lpszClassName = kPageantName;
	//
	//		if (not ::GetClassInfo(inst, lWndClass.lpszClassName, &lWndClass))
	//		{
	//			lWndClass.lpfnWndProc = &MCertificateStore::WndProc;
	//			lWndClass.hInstance = inst;
	//			::RegisterClass(&lWndClass);
	//		}
	//
	//		mPageant = ::CreateWindow(kPageantName, kPageantName,
	//				0, 0, 0, 0, 0, HWND_MESSAGE, NULL, inst, NULL);
	//	}
	//	catch (...)
	//	{
	//		mPageant = nullptr;
	//	}
	//}
}

MCertificateStore::~MCertificateStore()
{
	if (mEvent != nullptr)
		::CloseHandle(mEvent);

	if (mCertificateStore != nullptr)
		(void)::CertCloseStore(mCertificateStore, CERT_CLOSE_STORE_CHECK_FLAG);
}

void MCertificateStore::Check()
{
	if (::WaitForSingleObjectEx(mEvent, 0, false) == WAIT_OBJECT_0)
	{
		::CertControlStore(mCertificateStore, 0, CERT_STORE_CTRL_RESYNC, &mEvent);

		ssh_agent::instance().update();
	}
}

MCertificateStore& MCertificateStore::Instance()
{
	static MCertificateStore sInstance;
	return sInstance;
}

bool MCertificateStore::GetPublicKey(PCCERT_CONTEXT context, Integer& e, Integer& n)
{
	bool result = false;
	DWORD cbPublicKeyStruc = 0;
	PCERT_PUBLIC_KEY_INFO pk = &context->pCertInfo->SubjectPublicKeyInfo;
	
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
			
			if ((pks->aiKeyAlg & ALG_TYPE_RSA) != 0)
			{
				RSAPUBKEY* pkd = reinterpret_cast<RSAPUBKEY*>(&b[0] + sizeof(PUBLICKEYSTRUC));
				byte* data = reinterpret_cast<byte*>(&b[0] + sizeof(RSAPUBKEY) + sizeof(PUBLICKEYSTRUC));
				
				// public key is in little endian format
				uint32 len = pkd->bitlen / 8;
				reverse(data, data + len);

				e = pkd->pubexp;
				n = Integer(data, len);
				
				result = true;
			}
		}
	}
	
	return result;
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
				//uint8* p = nullptr;
				//HANDLE mapFile = nullptr;
				//
				//do
				//{
				//	COPYDATASTRUCT *cds = reinterpret_cast<COPYDATASTRUCT*>(lParam);
				//	if (cds == nullptr or cds->dwData != AGENT_COPYDATA_ID)
				//		break;
				//	
				//	char* fileName = reinterpret_cast<char*>(cds->lpData);
				//	if (fileName == nullptr or fileName[cds->cbData - 1] != 0)
				//		break;
				//	
				//	mapFile = ::OpenFileMappingA(FILE_MAP_ALL_ACCESS, false,
				//		fileName);
				//	if (mapFile == nullptr or mapFile == INVALID_HANDLE_VALUE)
				//		break;
				//	
				//	p = reinterpret_cast<uint8*>(::MapViewOfFile(mapFile, FILE_MAP_WRITE, 0, 0, 0));
				//	if (p == nullptr)
				//		break;
				//	
				//	HANDLE proc = ::OpenProcess(MAXIMUM_ALLOWED, false, ::GetCurrentProcessId());
				//	if (proc == nullptr)
				//		break;
				//	
				//	PSECURITY_DESCRIPTOR procSD = nullptr, mapSD = nullptr;
				//	PSID mapOwner, procOwner;
				//	
				//	if (::GetSecurityInfo(proc, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
				//			&procOwner, nullptr, nullptr, nullptr, &procSD) != ERROR_SUCCESS)
				//	{
				//		if (procSD != nullptr)
				//			::LocalFree(procSD);
				//		procSD = nullptr;
				//	}
				//	::CloseHandle(proc);
				//	
				//	if (::GetSecurityInfo(mapFile, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
				//		&mapOwner, nullptr, nullptr, nullptr, &mapSD) != ERROR_SUCCESS)
				//	{
				//		if (mapSD != nullptr)
				//			::LocalFree(mapSD);
				//		mapSD = nullptr;
				//	}
				//	
				//	if (::EqualSid(mapOwner, procOwner))
				//	{
				//		uint32 len = p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
				//		if (len < 10240)
				//		{
				//			MSshPacket in(p + 4, len);
				//			MSshPacket out;
				//			
				//			MSshAgent::Instance().ProcessAgentRequest(in, out);
				//			
				//			MSshPacket wrapped;
				//			wrapped << out;
	
				//			copy(wrapped.peek(), wrapped.peek() + wrapped.size(), p);
				//			result = 1;
				//		}
				//	}
				//	
				//	if (procSD != nullptr)
				//		::LocalFree(procSD);
				//	
				//	if (mapSD != nullptr)
				//		::LocalFree(mapSD);
				//}
				//while (false);

				//if (p != nullptr)
				//	::UnmapViewOfFile(p);
				//
				//if (mapFile != nullptr and mapFile != INVALID_HANDLE_VALUE)
				//	::CloseHandle(mapFile);

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

class MWinSshPrivateKeyImpl : public ssh_private_key_impl
{
  public:
		  					MWinSshPrivateKeyImpl(PCCERT_CONTEXT inCertificateContext,
		  						Integer& e, Integer& n);
	virtual					~MWinSshPrivateKeyImpl();

	virtual vector<uint8>	sign(const vector<uint8>& session_id, const opacket& p);

	virtual string			get_hash() const;
	virtual string			get_comment() const;

  private:
	PCCERT_CONTEXT			mCertificateContext;
};

MWinSshPrivateKeyImpl::MWinSshPrivateKeyImpl(PCCERT_CONTEXT inCertificateContext, Integer& e, Integer& n)
	: mCertificateContext(inCertificateContext)
{
	m_e = e;
	m_n = n;
}

MWinSshPrivateKeyImpl::~MWinSshPrivateKeyImpl()
{
	if (mCertificateContext != nullptr)
		::CertFreeCertificateContext(mCertificateContext);
}

vector<uint8> MWinSshPrivateKeyImpl::sign(const vector<uint8>& session_id, const opacket& inData)
{
	BOOL freeKey = false;
	DWORD keySpec, cb;
	HCRYPTPROV key;
	
	vector<uint8> digest;
	
	if (::CryptAcquireCertificatePrivateKey(mCertificateContext, 0, nullptr, &key, &keySpec, &freeKey))
	{
		HCRYPTHASH hash;

		if (::CryptCreateHash(key, CALG_SHA1, 0, 0, &hash))
		{
			const vector<uint8>& data(inData);
			
			if (::CryptHashData(hash, &session_id[0], session_id.size(), 0) and
				::CryptHashData(hash, &data[0], data.size(), 0))
			{
				cb = 0;
				::CryptSignHash(hash, keySpec, nullptr, 0, nullptr, &cb);
				
				if (cb > 0)
				{
					digest = vector<uint8>(cb);
					
					if (::CryptSignHash(hash, keySpec, nullptr, 0, &digest[0], &cb))
					{
						// data is in little endian format
						reverse(digest.begin(), digest.end());
					}
				}
			}
			
			::CryptDestroyHash(hash);
		}
		
		if (freeKey)
			::CryptReleaseContext(key, 0);
	}
	
	opacket signature;
	signature << "ssh-rsa" << digest;
	return signature;
}

string MWinSshPrivateKeyImpl::get_comment() const
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
//			comment = w2c(&b[0]);

			if (not comment.empty())
				break;
		}
	}

	return comment;
}

string MWinSshPrivateKeyImpl::get_hash() const
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

ssh_private_key_impl* ssh_private_key_impl::create_for_hash(const string& inHash)
{
//	string hash;
//
//	Base64Decoder d(new StringSink(hash));
//	d.Put(reinterpret_cast<const byte*>(inHash.c_str()), inHash.length());
//	d.MessageEnd();
//	
//	CRYPT_HASH_BLOB k;
//	k.cbData = hash.length();
//	k.pbData = const_cast<byte*>(reinterpret_cast<const byte*>(hash.c_str()));
//	
//	PCCERT_CONTEXT context = ::CertFindCertificateInStore(
//		MCertificateStore::Instance(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
//		0, CERT_FIND_SHA1_HASH, &k, nullptr);
//	
//	return new MWinSshPrivateKeyImpl(context);

	return nullptr;
}

ssh_private_key_impl* ssh_private_key_impl::create_for_blob(ipacket& inBlob)
{
	ssh_private_key_impl* result = nullptr;
	PCCERT_CONTEXT context = nullptr;
	MCertificateStore& store(MCertificateStore::Instance());
	
	while (context = ::CertEnumCertificatesInStore(store, context))
	{
		Integer e, n;
		
		if (store.GetPublicKey(context, e, n))
		{
			opacket blob;
			blob << "ssh-rsa" << e << n;
			
			if (blob == inBlob)
			{
				result = new MWinSshPrivateKeyImpl(context, e, n);
				break;
			}
		}
	}
	
	return result;
}

void ssh_private_key_impl::create_list(vector<ssh_private_key>& outKeys)
{
	MCertificateStore& store(MCertificateStore::Instance());
	PCCERT_CONTEXT context = nullptr;
	
	while (context = ::CertEnumCertificatesInStore(store, context))
	{
		Integer e, n;
		
		if (store.GetPublicKey(context, e, n))
			outKeys.push_back(ssh_private_key(new MWinSshPrivateKeyImpl(::CertDuplicateCertificateContext(context), e, n)));
	}
}

}
