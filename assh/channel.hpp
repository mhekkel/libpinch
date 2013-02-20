//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

namespace assh
{

class ipacket;
class opacket;
class basic_connection;

const uint32
	kMaxPacketSize = 0x8000,
	kWindowSize = 4 * kMaxPacketSize;

class channel
{
  public:
	void			reference();
	void			release();

	void			open();
	void			close();

	virtual void	setup(ipacket& in) = 0;
	virtual void	opened();
	virtual void	closed();

	void			open_pty(uint32 width, uint32 height,
						const std::string& terminal_type,
						bool forward_agent, bool forward_x11);

	void			send_request_and_command(const std::string& request,
						const std::string& command);

	uint32			my_channel_id() const		{ return m_my_channel_id; }
	bool			is_open() const				{ return m_channel_open; }
//	std::string		GetEncryptionParams() const;
//	std::string		GetHostVersion() const;

	virtual void	banner(const std::string& inMessage);
	virtual void	message(const std::string& inMessage);
	virtual void	error(const std::string& inMessage);

	virtual void	send_data(const char* data, std::size_t size);

	virtual void	process(ipacket& in);

	// boost::asio AsyncWriteStream interface
	
	boost::asio::io_service&
					get_io_service();

	template<class Handler>
	struct bound_handler
	{
		bound_handler(Handler&& handler, const boost::system::error_code& ec, std::size_t s)
			: m_handler(std::move(handler)), m_ec(ec), m_transferred(s)
		{
		}

		virtual void operator()()
		{
			m_handler(m_ec, m_transferred);
		}

		Handler							m_handler;
		const boost::system::error_code	m_ec;
		const std::size_t				m_transferred;
	};
	
	template<typename Handler>
	struct write_op
	{
					write_op(basic_connection& connection, std::list<opacket>&& p, Handler&& h)
						: m_connection(connection), m_packets(std::move(p)), m_handler(std::move(h)), m_transferred(0)
					{
					}
		
					write_op(write_op&& op)
						: m_connection(op.m_connection), m_packets(std::move(op.m_packets))
						, m_handler(std::move(op.m_handler)), m_transferred(op.m_transferred)
					{
					}
		
		void		operator()(const boost::system::error_code& ec, std::size_t bytes_transferred, bool first = false)
					{
						if (ec)
							m_handler(ec, 0);
						else
						{
							if (not first)
							{
								m_transferred += bytes_transferred;
								m_packets.pop_front();
							}
						
							if (not m_packets.empty())
								m_connection.async_write(m_packets.front(), write_op(std::move(*this)));
							else
								m_handler(ec, 0);
						}							
					}
		
		basic_connection&	m_connection;
		std::list<opacket>	m_packets;
		Handler				m_handler;
		std::size_t			m_transferred;
	};

	template<typename Handler>
	void			make_write_op(basic_connection& connection, std::list<opacket>&& p, Handler&& h)
					{
						write_op<Handler>(connection, std::move(p), std::move(h))
							(boost::system::error_code(), 0, true);
					}

	template <typename ConstBufferSequence, typename Handler>
	void			async_write_some(const ConstBufferSequence& buffers, Handler&& handler)
					{
						typedef read_handler<ConstBufferSequence,Handler> handler_type;
						boost::asio::io_service& io_service(get_io_service());

						size_t n = boost::asio::buffer_size(buffers); 

						if (not is_open())
							io_service.post(bound_handler<Handler>(std::move(handler),
								error::make_error_code(error::connection_lost), 0));
						else if (n == 0)
							io_service.post(bound_handler<Handler>(std::move(handler), boost::system::error_code(), 0));
						else
						{
							std::list<opacket> packets;
							
							foreach (const boost::asio::const_buffer& buffer, buffers)
							{
								const char* b = boost::asio::buffer_cast<const char*>(buffer);
								const char* e = b + n;
							
								while (b != e)
								{
									std::size_t k = e - b;
									if (k > m_max_send_packet_size)
										k = m_max_send_packet_size;
								
									packets.push_back(opacket(channel_data) << m_host_channel_id << std::make_pair(b, b + k));
								
									b += k;
								}
							}
							
							make_write_op(m_connection, packets, std::move(handler));
						}
					}

	struct basic_read_handler
	{
		typedef std::deque<char>::iterator	iterator;
		
		virtual				~basic_read_handler() {}
		virtual iterator	receive_and_post(iterator begin, iterator end, boost::asio::io_service& io_service) = 0;
	};

	template<class MutableBufferSequence, class Handler>
	struct read_handler : public basic_read_handler
	{
							read_handler(const MutableBufferSequence& buffer, Handler&& handler)
								: m_buffer(buffer), m_handler(std::move(handler)) {}

		virtual iterator	receive_and_post(iterator begin, iterator end, boost::asio::io_service& io_service)
							{
								std::size_t n = end - begin;
								if (n > boost::asio::buffer_size(m_buffer))
									n = boost::asio::buffer_size(m_buffer);
								char* ptr = boost::asio::buffer_cast<char*>(m_buffer);
								
								end = begin + n;
								std::copy(begin, end, ptr);
								
								io_service.post(bound_handler<Handler>(m_handler, boost::system::error_code(), n));
								
								return end;
							}
		
		MutableBufferSequence	m_buffer;
		Handler					m_handler;
	};

	template <typename MutableBufferSequence, typename Handler>
	void			async_read_some(const MutableBufferSequence& buffers, Handler&& handler)
					{
						typedef read_handler<MutableBufferSequence,Handler> handler_type;
						boost::asio::io_service& io_service(get_io_service());

						if (not is_open())
							io_service.post(bound_handler<Handler>(std::move(handler), error::make_error_code(error::connection_lost), 0));
						else if (boost::asio::buffer_size(buffers) == 0)
							io_service.post(bound_handler<Handler>(handler, boost::system::error_code(), 0));
						else
						{
							m_read_handlers.push_back(new read_handler(buffers, handler));
							
							if (not m_received.empty())
								push_received();
						}
					}



  protected:
//	friend class MSshConnection;

							channel(basic_connection& connection);
	virtual					~channel();

	virtual void			delete_this();

	//
	
	// To send data through the channel using SSH_MSG_CHANNEL_DATA messages
	virtual void			send_data(opacket& data);
	virtual void			send_extended_data(opacket& data, uint32 type);

	// send raw data as-is (without wrapping)
	void					send(opacket& data);
	
	// low level
	void					push(opacket&& p);
	opacket					pop();
	void					push_received();

	virtual void			receive_data(ipacket& data);
	virtual void			receive_extended_data(ipacket& data, uint32 inType);

	virtual void			receive_data(const char* data, std::size_t size);
	virtual void			receive_extended_data(const char* data, std::size_t size, uint32 type);

	virtual void			handle_channel_request(const std::string& request, ipacket& in, opacket& out);

  protected:

	basic_connection&		m_connection;

	uint32					m_max_send_packet_size;
	bool					m_channel_open;
	uint32					m_my_channel_id;
	uint32					m_host_channel_id;
	uint32					m_my_window_size;
	uint32					m_host_window_size;

	std::deque<opacket>		m_pending;
	std::deque<char>		m_received;
	std::deque<read_handler*>
							m_read_handlers;

  private:

	uint32					m_refcount;
	static uint32			s_next_channel_id;
};

}
