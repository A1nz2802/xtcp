# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -g

# Directories
SRC_DIR = src
OBJ_DIR = obj
INC_DIR = include

# Files
SRC = $(SRC_DIR)/main.c $(SRC_DIR)/tcp_utils.c
OBJ = $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
EXEC = xtcp

# Default rule
all: $(EXEC)

# Link objects to create the executable
$(EXEC): $(OBJ)
	$(CC) $(OBJ) -o $@

# Compile each .c file into a .o object file
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Create the obj directory if it doesn't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Clean compiled files
clean:
	rm -rf $(OBJ_DIR) $(EXEC)

# Phony targets
.PHONY: all clean
