# makefile for a gtk interface lib

firstTarget: static-lib

-include make.config

VERSION_MAJOR       = 3.5
VERSION_MINOR       = 0
VERSION             = $(VERSION_MAJOR).$(VERSION_MINOR)
DEFINES				+= VERSION='"$(VERSION)"'

LIB_NAME			= libassh

DIST_NAME           = $(LIB_NAME)$(VERSION)
SO_NAME             = $(LIB_NAME).so.$(VERSION_MAJOR)
SHARED_LIB_NAME     = $(SO_NAME).$(VERSION_MINOR)
STATIC_LIB_NAME		= $(LIB_NAME).a

OUTPUT				= ./

SHARED_LIB			= $(OUTPUT)/$(SHARED_LIB_NAME)
STATIC_LIB			= $(OUTPUT)/$(STATIC_LIB_NAME)

LIBDIR              ?= $(PREFIX)/lib
INCDIR              ?= $(PREFIX)/include
MANDIR              ?= $(PREFIX)/man/man3
DOCDIR              ?= $(PREFIX)/share/doc/libzeep-doc

CXX			?= clang++
PACKAGES	+= gtk+-3.0

# main build variables
# CXX                 ?= clangc++
CXXFLAGS            += -I. -pthread -std=c++17
CXXFLAGS            += -Wall -Wno-multichar
CXXFLAGS            += -g
LD                  ?= ld
LDFLAGS				= -g

SVN					= $(shell which svn)
MRC					= $(shell which mrc)

# Use the DEBUG flag to build debug versions of the code
DEBUG               ?= 0

ifneq ($(PACKAGES),)
CXXFLAGS			+= $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --cflags $(PACKAGES))
LDFLAGS				+= $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --libs $(PACKAGES) --static )
endif

ZEEP_DIR			?= ../../libzeep/

ZEEP_INC_DIR		= $(ZEEP_DIR:%=%/include)
ZEEP_LIB_DIR		= $(ZEEP_DIR:%=%/libs)

ZEEP_LIBS			= webapp rest http xml el generic
ZEEP_LIBS			:= $(ZEEP_LIBS:%=zeep-%)

BOOST_INC_DIR       = $(BOOST:%=%/)
BOOST_LIB_DIR       = $(BOOST:%=%/stage/lib)

BOOST_LIBS          = system thread filesystem regex random program_options date_time locale coroutine
BOOST_LIBS          := $(BOOST_LIBS:%=boost_%$(BOOST_LIB_SUFFIX))

LIBS                := $(ZEEP_LIBS) $(BOOST_LIBS) stdc++ m pthread $(LIBS)
LDFLAGS             += $(ZEEP_LIB_DIR:%=-L%) $(BOOST_LIB_DIR:%=-L%) $(LIBS:%=-l%) -g

ifeq "$(DEBUG)" "1"
DEFINES				+= DEBUG
else
CXXFLAGS			+= -O2
DEFINES				+= NDEBUG
endif

# targets

VPATH += src

CXXFLAGS			+= $(ZEEP_INC_DIR:%=-I%) $(BOOST_INC_DIR:%=-I%) -IGtk -IX11
CXXFLAGS			+= $(DEFINES:%=-D%)

OBJDIR = obj
ifeq "$(DEBUG)" "1"
	OBJDIR	:= $(OBJDIR).dbg
endif

$(OBJDIR):
	mkdir -p $(OBJDIR)

	# $(OBJDIR)/test-assh.o \
	# $(OBJDIR)/win_ssh_agent_impl.o \


OBJECTS = \
	$(OBJDIR)/channel.o \
	$(OBJDIR)/connection.o \
	$(OBJDIR)/connection_pool.o \
	$(OBJDIR)/debug.o \
	$(OBJDIR)/error.o \
	$(OBJDIR)/key_exchange.o \
	$(OBJDIR)/packet.o \
	$(OBJDIR)/port_forwarding.o \
	$(OBJDIR)/posix_ssh_agent_impl.o \
	$(OBJDIR)/proxy_cmd.o \
	$(OBJDIR)/sftp_channel.o \
	$(OBJDIR)/ssh_agent.o \
	$(OBJDIR)/terminal_channel.o \
	$(OBJDIR)/x11_channel.o

$(STATIC_LIB): $(OBJECTS)
	ar rc $@ $(OBJECTS)
	ranlib $@

$(SHARED_LIB): $(OBJECTS)
	$(CXX) -shared -o $(SHARED_LIB) -Wl,-soname=$(SO_NAME) $(OBJECTS) $(LDFLAGS)
	ln -fs $(SHARED_LIB_NAME) $(OUTPUT)/$(SO_NAME)
	ln -fs $(SHARED_LIB_NAME) $(OUTPUT)/$(LIB_NAME).so

ifeq "$(BUILD_STATIC_LIB)" "1"
BUILD_LIBS = $(STATIC_LIB)
endif

ifeq "$(BUILD_SHARED_LIB)" "1"
BUILD_LIBS += $(SHARED_LIB)
endif

libs: $(BUILD_LIBS)
.PHONY: libs

static-lib: $(STATIC_LIB)
.PHONY: static-lib

shared-lib: $(SHARED_LIB)
.PHONY: shared-lib

install-libs: $(SHARED_LIB)
	install -d $(LIBDIR)
	install $(SHARED_LIB) $(LIBDIR)/$(SHARED_LIB_NAME)
	strip --strip-unneeded $(LIBDIR)/$(SHARED_LIB_NAME)
	ln -Tfs $(SHARED_LIB_NAME) $(LIBDIR)/$(SO_NAME)
	ln -Tfs $(SHARED_LIB_NAME) $(LIBDIR)/$(LIB_NAME).so
	$(LD_CONFIG) -n $(LIBDIR)

install-dev: $(STATIC_LIB)
	install -d $(LIBDIR) $(INCDIR)/zeep/xml $(INCDIR)/zeep/http $(INCDIR)/zeep/http/webapp
	for f in $(HEADERS); do install ../include/$$f $(INCDIR)/$$f; done
	install $(STATIC_LIB) $(LIBDIR)/$(STATIC_LIB_NAME)
	strip -SX $(LIBDIR)/$(STATIC_LIB_NAME)

install: install-libs install-dev

-include $(OBJECTS:%.o=%.d)

$(OBJECTS:.o=.d):

$(OBJDIR)/%.o: %.cpp | $(OBJDIR)
	@ echo ">>" $<
	@ $(CXX) -MD -c -o $@ $< $(CFLAGS) $(CXXFLAGS)

clean:
	rm -rf $(OBJDIR)/* $(OUTPUT)/$(LIB_NAME)*

test:

dist-clean: clean

FORCE: