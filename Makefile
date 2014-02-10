# Makefile for project pds-flow
# Author: Martin Simon <xsimon14@stud.fit.vutbr.cz>

SRC=src/
DOC=doc/
BIN=bin/

ARCHIVE=xsimon14.zip
PDFFILE=$(DOC)pds-flow.pdf
EXE=flow

RM=rm -rf
AR=zip
HELP=-h


.PHONY: all src doc

all: src doc

src:
	make -C $(SRC)

doc:
	make -C $(DOC)

clean: clean-src clean-doc
	$(RM) $(ARCHIVE)

run:
	cd $(BIN) && ./$(EXE) $(HELP)

clean-src:
	make -C $(SRC) clean

clean-doc:
	make -C $(DOC) clean

pack: doc src clean
	$(AR) $(ARCHIVE) Makefile README INSTALL LICENSE $(SRC)* $(SRC)Makefile $(PDFFILE)
