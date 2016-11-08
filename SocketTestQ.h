#ifndef SOCKETTESTQ_H
#define SOCKETTESTQ_H

#include <QtGui>
#include <QtNetwork>
#include <QtWidgets>

#include "tcpportlist.h"
#include "udpportlist.h"

namespace Ui {
class SocketTestQ;
}

class SocketTestQ : public QWidget
{
    Q_OBJECT

public:
    explicit SocketTestQ(QWidget *parent = 0);
    ~SocketTestQ();

private slots:
    // Client
    void on_uiClientConnectBtn_clicked();
    void on_uiClientSendMsgBtn_clicked();
    void on_uiClientMsg_returnPressed();
    void ClientReceivedData();
    void ClientConnected();
    void ClientDisconnected();
    void SocketError(QAbstractSocket::SocketError error);
    void ClientOpenFileNameDialog();
    void ClientSaveLogFile();
    void ClientClearLogFile();
    void ClientSendFile();
    void WarnSecure();

    // Server
    void ServerListen();
    void NewClient();
    void ServerReceivedData();
    void ServerSendMsg();
    void ClientDisconnect(); // client disconnection
    void DisconnectClient();  // server kicks client
    void ServerOpenFileNameDialog();
    void ServerSaveLogFile();
    void ServerClearLogFile();
    void ServerSendFile();
    void WarnHex();

    void ShowTCPPortList();
    void ShowUDPPortList();

    // UDP
    void UDPListen();
    void UDPSendMsg();
    void UDPReceivedData();
    void UDPOpenFileNameDialog();
    void UDPSendFile();
    void UDPSaveLogFile();
    void UDPClearLogFile();


private:
    Ui::SocketTestQ *ui;
    TCPPortList m_TCPPortList;
    UDPPortList m_UDPPortList;

    // Used by Server
    QTcpServer* m_Server;
    QTcpSocket* m_ClientSocket;
    //QHash<QTcpSocket*,QByteArray*> m_ClientSockets; // for a future version ;) a client list will be dynamically created
    QByteArray* m_ServerByteArray;

    // Used by Client
    QTcpSocket* m_ServerSocket;
    QByteArray* m_ClientByteArray;

    // Used by UDP
    QUdpSocket* m_UDPSocket;
    QByteArray* m_UDPByteArray;

};

#endif // SOCKETTESTQ_H
