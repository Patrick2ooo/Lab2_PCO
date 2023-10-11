#ifndef MYTHREAD_H
#define MYTHREAD_H

#include <QString>
#include <pcosynchro/pcothread.h>

void monHack(QString hash, QString salt, QString currentPasswordString, QVector<unsigned int> currentPasswordArray, QString charset, unsigned int nbChars, long long unsigned int nbToCompute);

#endif// MYTHREAD_H
