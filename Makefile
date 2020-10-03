CC = gcc
CFLAGS = -g -Wall
LDFLAGS =
OBJFILES = ./crypto/aes.o ./crypto/sha256.o cstore.o
TARGET = cstore

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

.PHONY: test clean
clean:
	-@rm -f $(OBJFILES) $(TARGET) *.tar *~

test:
	@make -s test_add_and_list
	@make -s test_extract
	@make -s test_delete


test_add_and_list:
	@echo "\e[1;34mTESTING ADD AND LIST\e[0m"
	@echo "\e[1;34m--------------------\e[0m"
	@echo "This will test adding 3 files (alice.txt, bob.txt, cat.txt) and run cstore list to verify they are in the archive"
	@make -s clean
	@make -s
	@echo "TEST STRING FOR TESTING" >> alice.txt
	@echo "TEST STRING FOR TESTING" >> bob.txt
	@echo "TEST STRING FOR TESTING" >> cat.txt
	@./cstore add -p test newarchive.tar alice.txt bob.txt cat.txt
	@echo "\e[1;31mEXPECTATION: see alice.txt, bob.txt, cat.txt in the newarchive.tar\e[0m"
	@./cstore list newarchive.tar
	@rm alice.txt bob.txt cat.txt
	@make -s clean

test_extract:
	@echo "\e[1;34mTESTING EXTRACT\e[0m"
	@echo "\e[1;34m--------------------\e[0m"
	@echo "This will test adding and extracting a file"
	@make -s clean
	@make -s
	@echo "TEST STRING FOR TESTING" >> alice.txt
	@./cstore add -p test newarchive.tar alice.txt
	@mv alice.txt alice-source.txt
	@./cstore extract -p test newarchive.tar alice.txt
	@echo "\e[1;31mEXPECTATION: If the files are identical, then the diff should not output anything\e[0m"
	@diff -u alice.txt alice-source.txt || echo "THERE IS A DIFFERENCE. TEST FAILED"
	@echo ""
	@echo "\e[1;31mIf you see nothing between the two red lines, you PASSED! :D\e[0m"
	@rm alice.txt alice-source.txt
	@make -s clean

test_delete:
	@echo "\e[1;34mTESTING Delete\e[0m"
	@echo "\e[1;34m--------------------\e[0m"
	@echo "This will test adding,deleting, adding a file back"
	@make -s clean
	@make -s
	@echo "TEST STRING FOR TESTING" >> alice.txt
	@echo "TEST STRING 2 FOR TESING 2" >> bob.txt
	@./cstore add -p test newarchive.tar alice.txt bob.txt
	@./cstore delete -p test newarchive.tar alice.txt
	@./cstore add -p test newarchive.tar alice.txt
	@mv alice.txt alice-source.txt
	@./cstore extract -p test newarchive.tar alice.txt
	@echo "\e[1;31mEXPECTATION: If the files are identical, then the diff should not output anything\e[0m"
	@diff -u alice.txt alice-source.txt || echo "THERE IS A DIFFERENCE. TEST FAILED"
	@echo ""
	@echo "\e[1;31mIf you see nothing between the two red lines, you PASSED! :D\e[0m"
	@rm alice.txt alice-source.txt bob.txt
	@make -s clean