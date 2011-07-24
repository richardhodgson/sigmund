all : test

test :
	python src/tests.py

mirror :
	cd ../ && \
	hg convert sigmund sigmund.hg