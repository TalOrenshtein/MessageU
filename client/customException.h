#ifndef CE_H
#define CE_H
#include <iostream>
#include <string>
class customException : public std::exception {
public:
	std::string st;
	customException(std::string str) : st(str) {}
	~customException() throw () {}
	const char* what() const throw() { return st.c_str(); }
};

#endif
