//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <cassert>

#include <list>
#include <string>
#include <deque>

#include <boost/type_traits.hpp>
#include <boost/asio.hpp>

#include <assh/error.hpp>
#include <assh/packet.hpp>

namespace assh
{

class basic_connection;

const uint32
	kMaxPacketSize = 0x8000,
	kWindowSize = 4 * kMaxPacketSize;

class channel
{
  public:
	void			reference();
	void			release();

	struct basic_open_handler
	{
		virtual			~basic_open_handler() {}
		virtual void	operator()(const boost::system::error_code& ec) = 0;
	};
	
	template<typename Handler>
	struct open_handler : public basic_open_handler
	{
						open_handler(Handler&& handler) : m_handler(std::move(handler)) {}
		
		virtual void	operator()(const boost::system::error_code& ec)
						{
							BOOST_STATIC_ASSERT(boost::is_const<Handler>::value == false);

							m_handler(ec);
						}
		
		Handler			m_handler;
	};

	template<typename Handler>
	void			open(Handler&& handler)
					{
						m_open_handler = new open_handler<Handler>(std::move(handler));
						open();
					}

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

	virtual void	banner(const std::string& msg, const std::string& lang);
	virtual void	message(const std::string& msg, const std::string& lang);
	virtual void	error(const std::string& msg, const std::string& lang);

	virtual void	init(ipacket& in, opacket& out);
	virtual void	process(ipacket& in);

	// boost::asio AsyncWriteStream interface
	boost::asio::io_service&
					get_io_service();

	template<class Handler>
	struct bound_handler
	{
#if not defined(_MSC_VER)		// this is weird, MSVC does not compile this
		bound_handler(Handler&& handler, const boost::system::error_code& ec, std::size_t s)
			: m_handler(std::move(handler)), m_ec(ec), m_transferred(s)
		{
		}
#endif

		bound_handler(const Handler& handler, const boost::system::error_code& ec, std::size_t s)
			: m_handler(handler), m_ec(ec), m_transferred(s)
		{
		}

		virtual void operator()()
		{
			m_handler(m_ec, m_transferred);
		}

		Handler							m_handler;
		boost::system::error_code		m_ec;
		std::size_t						m_transferred;
	};

	struct basic_io_op
	{
		virtual				~basic_io_op() {}
		virtual void		written(const boost::system::error_code& ec, std::size_t bytes_transferred) = 0;
	};
	
	struct basic_write_op : public basic_io_op
	{
							basic_write_op(std::list<opacket>&& p)
								: m_packets(std::move(p))
							{
							}

							basic_write_op(opacket&& p)
							{
								m_packets.push_back(std::move(p));
							}
				
		std::list<opacket>	m_packets;
	};
	
	template<typename Handler>
	struct write_op : public basic_write_op
	{
							write_op(std::list<opacket>&& p, Handler&& h)
								: basic_write_op(std::move(p)), m_handler(std::move(h))
							{
							}
				
							write_op(opacket&& p, Handler&& h)
								: basic_write_op(std::move(p)), m_handler(std::move(h))
							{
							}
				
		virtual void		written(const boost::system::error_code& ec, std::size_t bytes_transferred)
							{
								try { m_handler(ec, bytes_transferred); } catch(...) {}
							}
		
		Handler				m_handler;
	};

	template<typename Handler>
	void			make_write_op(std::list<opacket>&& p, Handler&& h)
					{
						m_pending.push_back(new write_op<Handler>(std::move(p), std::move(h)));
						send_pending();
					}

	template<typename Handler>
	void			make_write_op(opacket&& p, Handler&& h)
					{
						m_pending.push_back(new write_op<Handler>(std::move(p), std::move(h)));
						send_pending();
					}

	template <typename ConstBufferSequence, typename Handler>
	void			async_write_some(const ConstBufferSequence& buffers, Handler&& handler)
					{
						typedef ConstBufferSequence							buffer_type;
						typedef read_op<ConstBufferSequence,Handler>	handler_type;
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
							
							for (typename buffer_type::const_iterator buffer = buffers.begin(); buffer != buffers.end(); ++buffer)
							{
								const char* b = boost::asio::buffer_cast<const char*>(*buffer);
								const char* e = b + n;
							
								while (b != e)
								{
									std::size_t k = e - b;
									if (k > m_max_send_packet_size)
										k = m_max_send_packet_size;
								
									packets.push_back(opacket(msg_channel_data) << m_host_channel_id << std::make_pair(b, k));
								
									b += k;
								}
							}
							
							make_write_op(std::move(packets), std::move(handler));
						}
					}

	struct basic_read_op
	{
		typedef std::deque<char>::iterator	iterator;
		
		virtual				~basic_read_op() {}
		virtual iterator	receive_and_post(iterator begin, iterator end, boost::asio::io_service& io_service) = 0;
		virtual void		post_error(const boost::system::error_code& ec, boost::asio::io_service& io_service) = 0;
	};

	template<class MutableBufferSequence, class Handler>
	struct read_op : public basic_read_op
	{
							read_op(read_op&& rhs)
								: m_buffer(std::move(rhs.m_buffer)), m_handler(std::move(rhs.m_handler)) {}

							read_op(const MutableBufferSequence& buffer, Handler&& handler)
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

		virtual void		post_error(const boost::system::error_code& ec, boost::asio::io_service& io_service)
							{
								io_service.post(bound_handler<Handler>(m_handler, ec, 0));
							}

		MutableBufferSequence	m_buffer;
		Handler					m_handler;
	};

	template <typename MutableBufferSequence, typename Handler>
	void			async_read_some(const MutableBufferSequence& buffers, Handler&& handler)
					{
						BOOST_STATIC_ASSERT(boost::is_const<Handler>::value == false);

						typedef read_op<MutableBufferSequence,Handler> handler_type;
						boost::asio::io_service& io_service(get_io_service());

						if (not is_open())
							io_service.post(bound_handler<Handler>(std::move(handler), error::make_error_code(error::connection_lost), 0));
						else if (boost::asio::buffer_size(buffers) == 0)
							io_service.post(bound_handler<Handler>(std::move(handler), boost::system::error_code(), 0));
						else
						{
							m_read_ops.push_back(new handler_type(buffers, std::move(handler)));
							
							if (not m_received.empty())
								push_received();
						}
					}



  protected:
							channel(basic_connection& connection);
	virtual					~channel();

	virtual void			delete_this();

	// To send data through the channel using SSH_MSG_CHANNEL_DATA messages

	void					send(opacket&& data)
							{
								make_write_op(std::move(data), [](const boost::system::error_code& ec, std::size_t bytes_transferred) {});
							}

	template<typename Handler>
	void 					send_data(const char* data, size_t size, Handler&& handler)
							{
								make_write_op(
									opacket(msg_channel_data) << m_host_channel_id << std::make_pair(data, size),
									std::move(handler));
							}
	
	template<typename Handler>
	void					send_data(opacket& data, Handler&& handler)
							{
								make_write_op(
									opacket(msg_channel_data) << m_host_channel_id << data,
									std::move(handler));
							}
							
	template<typename Handler>
	void					send_extended_data(opacket& data, uint32 type, Handler&& handler)
							{
								make_write_op(
									m_connection,
									opacket(msg_channel_extended_data) << m_host_channel_id << type << data,
									std::move(handler));
							}

	// low level
	void					send_pending();
	void					push_received();

	virtual void			receive_data(ipacket& data);
	virtual void			receive_extended_data(ipacket& data, uint32 inType);

	virtual void			receive_data(const char* data, std::size_t size);
	virtual void			receive_extended_data(const char* data, std::size_t size, uint32 type);

	virtual void			handle_channel_request(const std::string& request, ipacket& in, opacket& out);

  protected:

	basic_connection&		m_connection;
	basic_open_handler*		m_open_handler;

	uint32					m_max_send_packet_size;
	bool					m_channel_open, m_send_pending;
	uint32					m_my_channel_id;
	uint32					m_host_channel_id;
	uint32					m_my_window_size;
	uint32					m_host_window_size;

	std::deque<basic_write_op*>	m_pending;
	std::deque<char>			m_received;
	std::deque<basic_read_op*>	m_read_ops;

  private:

	uint32					m_refcount;
	static uint32			s_next_channel_id;
};

}
