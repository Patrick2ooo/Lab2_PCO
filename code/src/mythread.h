#ifndef MYTHREAD_H
#define MYTHREAD_H

#include <QString>
#include <pcosynchro/pcothread.h>
#include "threadmanager.h"

//class ThreadManager;

void monHack(QString hash, QString salt, QString currentPasswordString, QVector<unsigned int> currentPasswordArray, QString charset, unsigned int nbChars, long long unsigned int nbToCompute,long long unsigned int maxCompute , ThreadManager *threadManager);

#endif// MYTHREAD_H
