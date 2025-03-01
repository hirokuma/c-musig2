OUTPUT_FILENAME = tst
OUTPUT_BINARY_DIRECTORY = .

# source files
C_DIRECTORY = ./src
C_FILES += \
	common.c \
	signer.c \
	coodinator.c \
	main.c

# object files
OBJECT_DIRECTORY = _build

# test sources
TESTS_DIRECTORY = ./tests
TESTS_FILES += \

TESTS_SOURCE_FILES = $(addprefix $(TESTS_DIRECTORY)/, $(TESTS_FILES) )


# includes common to all targets(-I<dir>)
INC_PATHS = -I${HOME}/.local/include

# Link Library
LIBS = -L ${HOME}/.local/lib -lwallycore -lsecp256k1

CFLAGS =
LDFLAGS =


#GNU_PREFIX := arm-none-eabi-

# default target - first one defined
#	debug
#	release
#	tests
default: debug

###########################################

export OUTPUT_FILENAME
MAKEFILE_NAME := $(MAKEFILE_LIST)
MAKEFILE_DIR := $(dir $(MAKEFILE_NAME) )

MK := mkdir
RM := rm -rf

#echo suspend
ifeq ("$(VERBOSE)","1")
	NO_ECHO :=
else
	NO_ECHO := @
endif

# Toolchain commands
CC       		:= "$(GNU_PREFIX)gcc"
AS       		:= "$(GNU_PREFIX)as"
AR       		:= "$(GNU_PREFIX)ar" -r
LD       		:= "$(GNU_PREFIX)ld"
NM       		:= "$(GNU_PREFIX)nm"
OBJDUMP  		:= "$(GNU_PREFIX)objdump"
OBJCOPY  		:= "$(GNU_PREFIX)objcopy"
SIZE    		:= "$(GNU_PREFIX)size"

# function for removing duplicates in a list
# https://github.com/br101/pingcheck/blob/master/Makefile.default
rmdup = $(strip $(if $1,$(firstword $1) $(call rmdup,$(filter-out $(firstword $1),$1))))

######################################
# CFLAGS
######################################
CFLAGS += --std=gnu99
CFLAGS += -Wall

######################################
# LDFLAGS
######################################


#building all targets
all:
	$(NO_ECHO)$(MAKE) -f $(MAKEFILE_NAME) -C $(MAKEFILE_DIR) -e cleanobj
	$(NO_ECHO)$(MAKE) -f $(MAKEFILE_NAME) -C $(MAKEFILE_DIR) -e debug

#target for printing all targets
help:
	@echo following targets are available:
	@echo 	debug release


C_SOURCE_FILES = $(addprefix $(C_DIRECTORY)/, $(C_FILES))
C_SOURCE_FILE_NAMES = $(notdir $(C_SOURCE_FILES))
C_PATHS = $(call rmdup, $(dir $(C_SOURCE_FILES)))

C_OBJECTS = $(addprefix $(OBJECT_DIRECTORY)/, $(C_FILES:.c=.o))
OBJECTS = $(C_OBJECTS)
OBJECTS_DIRECTORIES = $(call rmdup, $(dir $(OBJECTS)))

# Sorting removes duplicates
BUILD_DIRECTORIES := $(sort $(OBJECTS_DIRECTORIES) $(OUTPUT_BINARY_DIRECTORY))

vpath %.c $(C_PATHS)

debug: CFLAGS += -DDEBUG
debug: CFLAGS += -ggdb3 -O0
debug: LDFLAGS += -ggdb3 -O0
debug: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo [DEBUG]Linking target: $(OUTPUT_FILENAME)
	@echo [DEBUG]CFLAGS=$(CFLAGS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

release: CFLAGS += -DNDEBUG -O3
release: LDFLAGS += -O3
release: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo [RELEASE]Linking target: $(OUTPUT_FILENAME)
	$(NO_ECHO)$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

tests: CFLAGS += -DDEBUG
tests: CFLAGS += -ggdb3 -O0
tests: LDFLAGS += -ggdb3 -O0
tests: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo [DEBUG]Linking target: $(OUTPUT_FILENAME)
	@echo [DEBUG]CFLAGS=$(CFLAGS)
	$(NO_ECHO)$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

## Create build directories
$(BUILD_DIRECTORIES):
	@$(MK) -p $@

# Create objects from C SRC files
$(OBJECT_DIRECTORY)/%.o: %.c
	@echo Compiling C file: $(notdir $<): $(CFLAGS)
	$(NO_ECHO)$(CC) $(CFLAGS) $(INC_PATHS) -c -o $@ $<

# Link
$(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME): $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo Linking target: $(OUTPUT_FILENAME)
	$(NO_ECHO)$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

leak:
	valgrind --tool=memcheck --leak-check=full ./tst

clean:
	$(RM) $(OBJECT_DIRECTORY) $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

.PHONY: leak
