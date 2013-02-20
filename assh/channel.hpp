//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

namespace assh
{

const uint32
	kMaxPacketSize = 0x8000,
	kWindowSize = 4 * kMaxPacketSize;

class channel
{
  public:
	void					reference();
	void					release();

	void					open();
	void					close();

	virtual void			setup(ipacket& in) = 0;
	virtual void			opened();
	virtual void			closed();

	void					open_pty(uint32 width, uint32 height,
								const std::string& terminal_type,
								bool forward_agent, bool forward_x11);

	void					SendRequestAndCommand(const std::string& inRequest,
								const std::string& inCommand);

	uint32					my_channel_id() const		{ return m_my_channel_id; }
	bool					is_open() const				{ return mChannelOpen; }
	std::string				GetEncryptionParams() const;
	std::string				GetHostVersion() const;

	virtual void			ChannelBanner(const std::string& inMessage);
	virtual void			ChannelMessage(const std::string& inMessage);
	virtual void			ChannelError(const std::string& inMessage);

	MEventIn<void(const std::string&)>		eConnectionMessage;
	MEventIn<void(const std::string&)>		eConnectionError;

	virtual void			Process(uint8 inMessage, ipacket& in);
	void					PushPending(ipacket& inData);
	bool					PopPending(ipacket& outData);

  protected:
//	friend class MSshConnection;

							MSshChannel(MSshConnection&	inConnection);
	virtual					~MSshChannel();

	virtual void			DeleteThis();

	// To send data through the channel using SSH_MSG_CHANNEL_DATA messages
	virtual void			SendData(ipacket& inData);
	virtual void			SendExtendedData(ipacket& inData, uint32 inType);

	// send raw data as-is (without wrapping)
	void					Send(ipacket& inData);

	virtual void			ReceiveData(ipacket& inData);
	virtual void			ReceiveExtendedData(ipacket& inData, uint32 inType);

	virtual void			ReceiveData(const char* inData, std::size_t inSize);
	virtual void			ReceiveExtendedData(const char* inData, std::size_t inSize,
								uint32 inType);

	virtual void			HandleChannelRequest(const std::string&	inRequest,
								ipacket& in, ipacket& out);

  protected:
	uint32					mMaxSendPacketSize;
	bool					mChannelOpen;
	MSshConnection&	mConnection;
	uint32					m_my_channel_id;
	uint32					m_host_channel_id;
	uint32					mMyWindowSize;
	uint32					mHostWindowSize;

  private:
	uint32					mRefCount;
	static uint32			sNextChannelId;

	std::deque<ipacket>	mPending;
};
	

};

}
