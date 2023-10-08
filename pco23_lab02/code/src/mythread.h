#ifndef MYTHREAD_H
#define MYTHREAD_H

#include <pcosynchro/pcothread.h>
#include <QString>

void monHack(QString hash, QString salt, QString currentPasswordString, QVector<unsigned int> currentPasswordArray, QString charset, unsigned int nbChars, long long unsigned int nbToCompute, QString &resultat);

#endif // MYTHREAD_H
