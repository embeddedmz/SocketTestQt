#include "SocketTestQ.h"
#include "ui_SocketTestQ.h"

#define MAX_HOSTNAME_LENGTH     255
#define my_delete(x) {delete x; x = 0;}

QSsl::SslProtocol             SocketTestQ::s_eSSLProtocol = QSsl::AnyProtocol;
QSslSocket::PeerVerifyMode    SocketTestQ::s_eSSLVerifyMode = QSslSocket::VerifyNone;
QString                       SocketTestQ::s_qstrCertFile;
QString                       SocketTestQ::s_qstrKeyFile;

SocketTestQ::SocketTestQ(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SocketTestQ),
    m_bSecure(false), // client
    m_bSecureServer(false)
{
    // ************** Miscellaneous
    // **************
    ui->setupUi(this);
    setFixedSize(geometry().width(),geometry().height());
    //setWindowTitle(tr("SocketTestQ v 1.0.0"));

    // ************** Server
    // **************
    m_Server = new QTcpServer(this);
    m_pSecureServer = new CSSLServer(this);
    m_ClientSocket = 0;
    m_ServerByteArray = new QByteArray();

    // Connection between signals and slots of buttons
    connect(ui->uiServerListenBtn, SIGNAL(clicked()), this, SLOT(ServerListen()));
    connect(ui->uiServerPortListBtn, SIGNAL(clicked()), this, SLOT(ShowTCPPortList()));

    connect(ui->uiServerSendMsgBtn, SIGNAL(clicked()), this, SLOT(ServerSendMsg()));
    connect(ui->uiServerBrowseBtn, SIGNAL(clicked()), this, SLOT(ServerOpenFileNameDialog()));
    connect(ui->uiServerSendFileBtn, SIGNAL(clicked()), this, SLOT(ServerSendFile()));

    connect(ui->uiServerSaveLogBtn, SIGNAL(clicked()), this, SLOT(ServerSaveLogFile()));
    connect(ui->uiServerClearLogBtn, SIGNAL(clicked()), this, SLOT(ServerClearLogFile()));
    connect(ui->uiServerDisconnectBtn, SIGNAL(clicked()), this, SLOT(DisconnectClient()));
    connect(ui->uiServerRadioHex, SIGNAL(clicked()), this, SLOT(WarnHex()));
    connect(ui->uiServerSecure, SIGNAL(clicked()), this, SLOT(CheckSSLServerSetup()));
    connect(ui->uiBtnLoadKey, SIGNAL(clicked()), this, SLOT(PrivateKeyDialog()));
    connect(ui->uiBtnLoadCert, SIGNAL(clicked()), this, SLOT(CertDialog()));

    // Connection between signals and slots of non-gui elements (network communication)
    connect(m_Server, SIGNAL(newConnection()), this, SLOT(NewClient()));
    // SSL
    connect(this, SIGNAL(DisconnectSSLClient()), m_pSecureServer, SLOT(SSLClientDisconnect()));
    connect(this, SIGNAL(SendSSLData(const QByteArray&)), m_pSecureServer, SLOT(onSSLSendData(const QByteArray&)));

    // ************** Client
    // ************** autoconnect has been used for a few client's widgets
    m_ServerSocket = new QSslSocket(this);
    m_ServerSocket->setPeerVerifyMode(QSslSocket::VerifyNone);
    m_ClientByteArray = new QByteArray();

    // Connection between signals and slots of non-gui elements (network communication)
    connect(m_ServerSocket, SIGNAL(readyRead()), this, SLOT(ClientReceivedData()));
    connect(m_ServerSocket, SIGNAL(connected()), this, SLOT(ClientConnected()));
    connect(m_ServerSocket, SIGNAL(disconnected()), this, SLOT(ClientDisconnected()));
    connect(m_ServerSocket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(SocketError(QAbstractSocket::SocketError)));
    /* used only in Secure Mode */
    connect(m_ServerSocket, SIGNAL(encrypted()), this, SLOT(SocketEncrypted()));
    connect(m_ServerSocket, SIGNAL(sslErrors(const QList<QSslError>&)), this, SLOT(SslErrors(const QList<QSslError>&)));

    // Connection between signals and slots of buttons
    connect(ui->uiClientPortListBtn, SIGNAL(clicked()), this, SLOT(ShowTCPPortList()));
    connect(ui->uiClientRadioHex, SIGNAL(clicked()), this, SLOT(WarnHex()));
    connect(ui->uiClientBrowseBtn, SIGNAL(clicked()), this, SLOT(ClientOpenFileNameDialog()));
    connect(ui->uiClientSendFileBtn, SIGNAL(clicked()), this, SLOT(ClientSendFile()));
    connect(ui->uiClientSaveLogBtn, SIGNAL(clicked()), this, SLOT(ClientSaveLogFile()));
    connect(ui->uiClientClearLogBtn, SIGNAL(clicked()), this, SLOT(ClientClearLogFile()));
    connect(ui->uiClientSecureCheck, SIGNAL(clicked()), this, SLOT(CheckSSLSupport()));

    // ************** UDP
    // **************
    m_UDPSocket = new QUdpSocket(this);
    m_UDPByteArray = new QByteArray();

    // Connection between signals and slots of non-gui elements (network communication)
    connect(m_UDPSocket, SIGNAL(readyRead()), this, SLOT(UDPReceivedData()));

    // Connection between signals and slots of buttons
    connect(ui->uiUdpServerListenBtn, SIGNAL(clicked()), this, SLOT(UDPListen()));
    connect(ui->uiUdpSendMsgBtn, SIGNAL(clicked()), this, SLOT(UDPSendMsg()));
    connect(ui->uiUdpBrowseBtn, SIGNAL(clicked()), this, SLOT(UDPOpenFileNameDialog()));
    connect(ui->uiUdpSendFileBtn, SIGNAL(clicked()), this, SLOT(UDPSendFile()));
    connect(ui->uiUdpSaveLogBtn, SIGNAL(clicked()), this, SLOT(UDPSaveLogFile()));
    connect(ui->uiUdpClearLogBtn, SIGNAL(clicked()), this, SLOT(UDPClearLogFile()));
    connect(ui->uiUdpServerPortListBtn, SIGNAL(clicked()), this, SLOT(ShowUDPPortList()));
    connect(ui->uiUdpClientPortListBtn, SIGNAL(clicked()), this, SLOT(ShowUDPPortList()));
    connect(ui->uiUdpRadioHex, SIGNAL(clicked()), this, SLOT(WarnHex()));
}

// ************** Server
// **************

void SocketTestQ::ServerListen()
{
    ui->uiServerSecure->setEnabled(false);
    m_bSecureServer = (ui->uiServerSecure->isChecked()) ? true : false;
    QTcpServer* pCurrentServer = (m_bSecureServer) ? m_pSecureServer : m_Server;

    if(pCurrentServer->isListening())
    {
        pCurrentServer->close();
        ui->uiServerListenBtn->setText( tr("Start Listening") );
        (!m_bSecureServer) ? ui->uiServerLog->append(tr("Server stopped"))
                           : ui->uiServerLog->append(tr("SSL Server stopped"));
        ui->uiServerSecure->setEnabled(true);
        return;
    }

    if((ui->uiServerIP->text()).length() <= MAX_HOSTNAME_LENGTH )
    {
        QHostAddress ServerAddress(ui->uiServerIP->text()); // if this ctor is not explicit, we can put the text directly on listen()

        if ( !pCurrentServer->listen(ServerAddress, ui->uiServerPort->value() ) )
        {
            QMessageBox::critical(this, (m_bSecureServer) ? tr("Secure Server Error") : tr("Server Error"),
                                        tr("Server couldn't start. Reason :<br />") + pCurrentServer->errorString());
            ui->uiServerSecure->setEnabled(true);
        }
        else
        {
            ui->uiServerListenBtn->setText( tr("Stop Listening") );
            ui->uiServerLog->append((m_bSecureServer) ? tr("Secure Server Started\r\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~") :
                                                        tr("Server Started\r\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
        }
    }
    else
    {
        QMessageBox::critical(this, (m_bSecureServer) ? tr("Secure TCP Server Error") : tr("TCP Server Error"),
                                    tr("IP address / hostname is too long !"));
        ui->uiServerSecure->setEnabled(true);
    }
}

void SocketTestQ::NewClient()
{
    if(!m_ClientSocket && m_Server->hasPendingConnections() ) // we accept only one client in version 1.0.0
    {
        m_ClientSocket = m_Server->nextPendingConnection();

        connect(m_ClientSocket, SIGNAL(readyRead()), this, SLOT(ServerReceivedData())); // append bytes in Log
        connect(m_ClientSocket, SIGNAL(disconnected()), this, SLOT(ClientDisconnect()));

        ui->uiServerGroupBoxConnection->setTitle( tr("Connected Client : < ") + (m_ClientSocket->peerAddress()).toString() +tr(" >") );

        //ui->uiServerLog->append(tr("New Client: ") + m_ClientSocket->peerName()); // empty
        ui->uiServerLog->append(tr("New Client addr: ") + (m_ClientSocket->peerAddress()).toString());

        ui->uiServerSendMsgBtn->setEnabled(true);
        ui->uiServerSendFileBtn->setEnabled(true);
        ui->uiServerBrowseBtn->setEnabled(true);
        ui->uiServerDisconnectBtn->setEnabled(true);
    }
}

void SocketTestQ::ClientDisconnect()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender()); // similar to dynamic_cast
    if (socket == 0)
        return;

    socket->deleteLater();
    ui->uiServerSendMsgBtn->setEnabled(false);
    ui->uiServerSendFileBtn->setEnabled(false);
    ui->uiServerBrowseBtn->setEnabled(false);
    ui->uiServerDisconnectBtn->setEnabled(false);
    m_ClientSocket = 0;
    ui->uiServerGroupBoxConnection->setTitle( tr("Connected Client : < NONE >") );
    ui->uiServerLog->append(tr("Client closed conection."));
}

void SocketTestQ::DisconnectClient()
{
    if(!m_bSecureServer)
    {
        if (m_ClientSocket)
        {
            m_ClientSocket->deleteLater();
            ui->uiServerSendMsgBtn->setEnabled(false);
            ui->uiServerSendFileBtn->setEnabled(false);
            ui->uiServerBrowseBtn->setEnabled(false);
            ui->uiServerDisconnectBtn->setEnabled(false);
            m_ClientSocket = 0;
            ui->uiServerGroupBoxConnection->setTitle( tr("Connected Client : < NONE >") );
            ui->uiServerLog->append(tr("Server closed client connection."));
        }
        return;
    }

    // SSL
    emit DisconnectSSLClient();
}

// TODO : store rcvd data in a file for next version
void SocketTestQ::ServerReceivedData()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender()); // which client has sent data
    if (socket == 0)
        return;

    while (socket->bytesAvailable() > 0)
    {
        m_ServerByteArray->append(socket->readAll());
        if(ui->uiServerRadioHex->isChecked())
        {
            ui->uiServerLog->append(QString(m_ServerByteArray->toHex())); // TODO : make it more pretty to the user (tpUpper+separated symbols)
        }
        else
        {
            ui->uiServerLog->append(QString(*m_ServerByteArray));
        }
        m_ServerByteArray->remove(0, m_ServerByteArray->size() );
    }
}

void SocketTestQ::WarnHex()
{
    QMessageBox::warning(this, tr("Hex mode"), tr("Experimental feature. Please send me your suggestion."));
}

void SocketTestQ::ServerSendMsg()
{
    QByteArray packet;

    if (ui->uiServerRadioHex->isChecked())
    {
        bool bNonHexSymbol = false;
        QString strTmp = ui->uiServerMsg->text().toUpper();

        for(int c=0; c < strTmp.toUtf8().length(); c++)
        {
            if (strTmp.toUtf8().at(c) >= '0' && strTmp.toUtf8().at(c) <= '9')
            {
                packet.append( (strTmp.toUtf8().at(c) - 48) );
                qDebug() << (strTmp.toUtf8().at(c) - 48);
            }
            else if(strTmp.toUtf8().at(c) >= 'A' && strTmp.toUtf8().at(c) <= 'F' )
            {
                packet.append( (strTmp.toUtf8().at(c) - 55) );
                qDebug() << (strTmp.toUtf8().at(c) - 55);
            }
            else
                bNonHexSymbol = true;
        }
        if (bNonHexSymbol)
            QMessageBox::warning(this, tr("Non Hexadecimal symbols"), tr("Detected non hexadecimal symbols in the message. They will not be sent."));
    }
    else
    {
        for(int c=0; c < ui->uiServerMsg->text().toUtf8().length(); c++)
            packet.append( ui->uiServerMsg->text().toUtf8().at(c) );

        if (ui->uiServerRadioNull->isChecked())
            packet.append( (char)'\0' ); // NULL
        else if (ui->uiServerRadioCRLF->isChecked())
        {
            packet.append( (char)'\r' ); // CR
            packet.append( (char)'\n' ); // LF
        }
    }

    if (!m_bSecureServer)
        m_ClientSocket->write(packet);
    else
        emit SendSSLData(packet);

    (!m_bSecureServer) ? ui->uiServerLog->append("[=>] : " + ui->uiServerMsg->text())
                       : ui->uiServerLog->append("[Encrypted =>] : " + ui->uiServerMsg->text());
    ui->uiServerMsg->setText("");
}

void SocketTestQ::ServerOpenFileNameDialog()
{
    ui->uiServerFile->setText(QFileDialog::getOpenFileName(this, tr("Open a file"), QString(), "*.*"));
}

void SocketTestQ::ServerSaveLogFile()
{
    QFile file(QFileDialog::getSaveFileName(this, tr("Save log file"), QString(), "Text files (*.txt);;*.*"));

    // Trying to open in WriteOnly and Text mode
    if(!file.open(QFile::WriteOnly |
                  QFile::Text))
    {
        QMessageBox::critical(this, tr("File Error"), tr("Could not open file for writing !"));
        return;
    }

    // To write text, we use operator<<(),
    // which is overloaded to take
    // a QTextStream on the left
    // and data types (including QString) on the right

    QTextStream out(&file);
    out << ui->uiServerLog->toPlainText(); // or file.write(byteArray);
    file.flush();
    file.close();
}

void SocketTestQ::ServerClearLogFile()
{
    ui->uiServerLog->clear();
}

void SocketTestQ::ShowTCPPortList()
{
    m_TCPPortList.show();
}

void SocketTestQ::ShowUDPPortList()
{
    m_UDPPortList.show();
}

void SocketTestQ::ServerSendFile()
{
    if(ui->uiServerFile->text().isEmpty())
        QMessageBox::critical(this, tr("File Error"), tr("Enter a file path !"));
    else
    {
        QFile file(ui->uiServerFile->text());
        if(!file.open(QFile::ReadOnly))
        {
            QMessageBox::critical(this, tr("File Error"), tr("Could not open the file for reading."));
            return;
        }

        QByteArray packet = file.readAll();

        if (!m_bSecureServer)
            m_ClientSocket->write(packet);
        else
            emit SendSSLData(packet);

        file.close();
        (!m_bSecureServer) ? ui->uiServerLog->append("[=>] File was sent to connected client.")
                           : ui->uiServerLog->append("[=>] File was sent to connected SSL client.");
    }
}

/******** Client ********/

// Connection attempt to a server
void SocketTestQ::on_uiClientConnectBtn_clicked()
{
    //bool bUnconnected = !m_ServerSocket || m_ServerSocket->state() == QAbstractSocket::UnconnectedState;
    bool bConnected = m_ServerSocket->state() == QAbstractSocket::ConnectedState; // no need to check for nullptr.
    if (bConnected) // m_ServerSocket->isOpen()
    {
        m_ServerSocket->close();
        return;
    }

    m_bSecure = (ui->uiClientSecureCheck->isChecked()) ? true : false;

    ui->uiClientLog->append(tr("<em>Attempting to connect...</em>"));

    m_ServerSocket->abort(); // disable previous connections if they exist

    if (m_bSecure)
    {
        m_ServerSocket->setProtocol(s_eSSLProtocol);
        m_ServerSocket->setPeerVerifyMode(s_eSSLVerifyMode);

        /* Set the certificate and private key. */
        m_ServerSocket->setLocalCertificate(s_qstrCertFile);
        m_ServerSocket->setPrivateKey(s_qstrKeyFile);

        /* connection to the requested SSL/TLS server */
        m_ServerSocket->connectToHostEncrypted(ui->uiClientDstIP->text(), ui->uiClientDstPort->value());
    }
    else
    {
        /* connection to the requested unencrypted server */
        m_ServerSocket->connectToHost(ui->uiClientDstIP->text(), ui->uiClientDstPort->value());
    }
}

void SocketTestQ::SocketEncrypted()
{
    if (!m_bSecure)
        return;

    QSslSocket* pSocket = qobject_cast<QSslSocket*>(m_ServerSocket);
    if (pSocket == 0)
        return; // or might have disconnected already

    // get the peer's certificate
    //QSslCertificate certCli = pSocket->peerCertificate();

    QSslCipher ciph = pSocket->sessionCipher();
    m_qstrCipher = QString("%1, %2 (%3/%4)").arg(ciph.authenticationMethod())
                     .arg(ciph.name()).arg(ciph.usedBits()).arg(ciph.supportedBits());

    ui->uiClientGroupBoxConnection->setTitle( tr("Connected To < ") + (m_ServerSocket->peerAddress()).toString()
                                              + ((m_bSecure) ? (tr(" > Cipher : ") + m_qstrCipher) : tr(" > Unencrypted")) );
}

void SocketTestQ::SslErrors(const QList<QSslError>& listErrors)
{
    listErrors; // unreferenced_parameter

    m_ServerSocket->ignoreSslErrors();
}

// Sending msg to server
void SocketTestQ::on_uiClientSendMsgBtn_clicked()
{
    QByteArray packet;

    if (ui->uiClientRadioHex->isChecked())
    {
        bool bNonHexSymbol = false;
        QString strTmp = ui->uiClientMsg->text().toUpper();

        for(int c=0; c < strTmp.toUtf8().length(); c++)
        {
            if (strTmp.toUtf8().at(c) >= '0' && strTmp.toUtf8().at(c) <= '9')
            {
                packet.append( (strTmp.toUtf8().at(c) - 48) );
                qDebug() << (strTmp.toUtf8().at(c) - 48);
            }
            else if(strTmp.toUtf8().at(c) >= 'A' && strTmp.toUtf8().at(c) <= 'F' )
            {
                packet.append( (strTmp.toUtf8().at(c) - 55) );
                qDebug() << (strTmp.toUtf8().at(c) - 55);
            }
            else
                bNonHexSymbol = true;
        }
        if (bNonHexSymbol)
            QMessageBox::warning(this, tr("Non Hexadecimal symbols"), tr("Detected non hexadecimal symbols in the message. They will not be sent."));
    }
    else
    {
        for(int c=0; c < ui->uiClientMsg->text().toUtf8().length(); c++)
            packet.append( ui->uiClientMsg->text().toUtf8().at(c) );

        if (ui->uiClientRadioNull->isChecked())
            packet.append( (char)'\0' ); // NULL
        else if (ui->uiClientRadioCRLF->isChecked())
        {
            packet.append( (char)'\r' ); // CR
            packet.append( (char)'\n' ); // LF
        }
    }

    m_ServerSocket->write(packet);

    ui->uiClientLog->append("[=>] : " + ui->uiClientMsg->text());
    ui->uiClientMsg->clear();
    ui->uiClientMsg->setFocus(); // set the focus inside it
}

// Pressing "Enter" has the same effect than clicking on "Send" button
void SocketTestQ::on_uiClientMsg_returnPressed()
{
    if (ui->uiClientSendMsgBtn->isEnabled())
        on_uiClientSendMsgBtn_clicked();
}

// packet received or a sub-packet
void SocketTestQ::ClientReceivedData()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender()); // which client has sent data
    if (socket == 0)
        return;

    while (socket->bytesAvailable() > 0)
    {
        m_ClientByteArray->append(socket->readAll());
        if(ui->uiClientRadioHex->isChecked())
        {
            ui->uiClientLog->append(QString(m_ClientByteArray->toHex()));
        }
        else
        {
            ui->uiClientLog->append(QString(*m_ClientByteArray));
        }
        m_ClientByteArray->remove(0, m_ClientByteArray->size() );
    }
}

// this slot gets called when the connection to the remote destination has succeeded.
void SocketTestQ::ClientConnected()
{
    ui->uiClientLog->append(tr("<em>Connected !</em>"));
    ui->uiClientConnectBtn->setText(tr("Disconnect"));
    if (!m_bSecure)
        ui->uiClientGroupBoxConnection->setTitle(tr("Connected To < ") + (m_ServerSocket->peerAddress()).toString() +tr(" >"));
    ui->uiClientSendMsgBtn->setEnabled(true);
    ui->uiClientSendFileBtn->setEnabled(true);
    ui->uiClientBrowseBtn->setEnabled(true);
}

// this slot gets called when the client gets disconnected
void SocketTestQ::ClientDisconnected()
{
    ui->uiClientGroupBoxConnection->setTitle(tr("Connected to < NONE >"));
    ui->uiClientConnectBtn->setText(tr("Connect"));
    ui->uiClientSendMsgBtn->setEnabled(false);
    ui->uiClientSendFileBtn->setEnabled(false);
    ui->uiClientBrowseBtn->setEnabled(false);
}

// this slot gets called when there is a socket related error
void SocketTestQ::SocketError(QAbstractSocket::SocketError error)
{
    switch(error) // On affiche un message différent selon l'erreur qu'on nous indique
    {
        case QAbstractSocket::HostNotFoundError:
            QMessageBox::critical(this, tr("Opening connection"), tr("Connection refused, server not found, check IP and Port "));
            break;
        case QAbstractSocket::ConnectionRefusedError:
            QMessageBox::critical(this, tr("Opening connection"), tr("Connection refused, server refused the connection, check IP and Port and that server is available"));
            break;
        case QAbstractSocket::RemoteHostClosedError:
            QMessageBox::warning(this, tr("Disconnected"), tr("Server closed the connection "));
            break;
        default:
            QMessageBox::critical(this, tr("Information"), tr("<em>ERROR : ") + m_ServerSocket->errorString() + tr("</em>"));
    }

    ui->uiClientConnectBtn->setText(tr("Connect"));
}

void SocketTestQ::ClientOpenFileNameDialog()
{
    ui->uiClientFile->setText(QFileDialog::getOpenFileName(this, tr("Open a file"), QString(), "*.*"));
}

void SocketTestQ::ClientSaveLogFile()
{
    QFile file(QFileDialog::getSaveFileName(this, tr("Save log file"), QString(), "Text files (*.txt);;*.*"));

    // Trying to open in WriteOnly and Text mode
    if(!file.open(QFile::WriteOnly |
                  QFile::Text))
    {
        QMessageBox::critical(this, tr("File Error"), tr("Could not open file for writing !"));
        return;
    }

    // To write text, we use operator<<(),
    // which is overloaded to take
    // a QTextStream on the left
    // and data types (including QString) on the right

    QTextStream out(&file);
    out << ui->uiClientLog->toPlainText(); // or file.write(byteArray);
    file.flush();
    file.close();
}

void SocketTestQ::ClientClearLogFile()
{
    ui->uiClientLog->clear();
}

void SocketTestQ::ClientSendFile()
{
    if(ui->uiClientFile->text().isEmpty())
        QMessageBox::critical(this, tr("File Error"), tr("Enter a file path !"));
    else
    {
        QFile file(ui->uiClientFile->text());
        if(!file.open(QFile::ReadOnly))
        {
            QMessageBox::critical(this, tr("File Error"), tr("Could not open the file for reading."));
            return;
        }

        QByteArray packet = file.readAll();

        m_ServerSocket->write(packet);

        file.close();
        ui->uiClientLog->append("[=>] File was sent to server.");
    }
}

/******** UDP ********/

void SocketTestQ::UDPListen()
{
    if(m_UDPSocket->state() != QAbstractSocket::UnconnectedState)
    {
        m_UDPSocket->close();
        ui->uiUdpServerListenBtn->setText( tr("Start Listening") );
        ui->uiUdpLog->append(tr("UDP Server stopped"));
        return;
    }

    if((ui->uiServerIP->text()).length() <= MAX_HOSTNAME_LENGTH )
    {
        QHostAddress ServerAddress(ui->uiUdpServerIp->text());

        if ( !m_UDPSocket->bind(ServerAddress,ui->uiUdpServerPort->value()) )
        {
            QMessageBox::critical(this, tr("UDP Server Error"), tr("UDP server couldn't start. Reason :<br />") + m_UDPSocket->errorString());
        }
        else
        {
            ui->uiUdpServerListenBtn->setText( tr("Stop Listening") );
            ui->uiUdpLog->append(tr("Server Started on Port : ") + QString::number(ui->uiUdpServerPort->value()));
        }
    }
    else
    {
        QMessageBox::critical(this, tr("UDP Server Error"), tr("IP address / hostname is too long !"));
    }
}

void SocketTestQ::UDPSendMsg()
{
    QByteArray packet;

    if (ui->uiUdpRadioHex->isChecked())
    {
        bool bNonHexSymbol = false;
        QString strTmp = ui->uiUdpMsg->text().toUpper();

        for(int c=0; c < strTmp.toUtf8().length(); c++)
        {
            if (strTmp.toUtf8().at(c) >= '0' && strTmp.toUtf8().at(c) <= '9')
            {
                packet.append( (strTmp.toUtf8().at(c) - 48) );
                qDebug() << (strTmp.toUtf8().at(c) - 48);
            }
            else if(strTmp.toUtf8().at(c) >= 'A' && strTmp.toUtf8().at(c) <= 'F' )
            {
                packet.append( (strTmp.toUtf8().at(c) - 55) );
                qDebug() << (strTmp.toUtf8().at(c) - 55);
            }
            else
                bNonHexSymbol = true;
        }
        if (bNonHexSymbol)
            QMessageBox::warning(this, tr("Non Hexadecimal symbols"), tr("Detected non hexadecimal symbols in the message. They will not be sent."));
    }
    else
    {
        for(int c=0; c < ui->uiUdpMsg->text().toUtf8().length(); c++)
            packet.append( ui->uiUdpMsg->text().toUtf8().at(c) );

        if (ui->uiUdpRadioNull->isChecked())
            packet.append( (char)'\0' ); // NULL
        else if (ui->uiUdpRadioCRLF->isChecked())
        {
            packet.append( (char)'\r' ); // CR
            packet.append( (char)'\n' ); // LF
        }
    }

    m_UDPSocket->writeDatagram(packet, QHostAddress(ui->uiUdpClientIp->text()), ui->uiUdpClientPort->value());

    ui->uiUdpLog->append("[=>] : " + ui->uiUdpMsg->text());
    ui->uiUdpMsg->clear();
}

void SocketTestQ::UDPSaveLogFile()
{
    QFile file(QFileDialog::getSaveFileName(this, tr("Save log file"), QString(), "Text files (*.txt);;*.*"));

    // Trying to open in WriteOnly and Text mode
    if(!file.open(QFile::WriteOnly |
                  QFile::Text))
    {
        QMessageBox::critical(this, tr("File Error"), tr("Could not open file for writing !"));
        return;
    }

    // To write text, we use operator<<(),
    // which is overloaded to take
    // a QTextStream on the left
    // and data types (including QString) on the right

    QTextStream out(&file);
    out << ui->uiUdpLog->toPlainText(); // or file.write(byteArray);
    file.flush();
    file.close();
}

void SocketTestQ::UDPClearLogFile()
{
    ui->uiUdpLog->clear();
}

void SocketTestQ::UDPOpenFileNameDialog()
{
    ui->uiUdpFile->setText(QFileDialog::getOpenFileName(this, tr("Open a file"), QString(), "*.*"));
}

void SocketTestQ::UDPSendFile()
{
    if(ui->uiUdpFile->text().isEmpty())
        QMessageBox::critical(this, tr("File Error"), tr("Enter a file path !"));
    else
    {
        QFile file(ui->uiUdpFile->text());
        if(!file.open(QFile::ReadOnly))
        {
            QMessageBox::critical(this, tr("File Error"), tr("Could not open the file for reading."));
            return;
        }

        QByteArray packet = file.readAll();

        m_UDPSocket->writeDatagram(packet, QHostAddress(ui->uiUdpClientIp->text()), ui->uiUdpClientPort->value());

        file.close();
        ui->uiUdpLog->append("[=>] File was sent.");
    }
}

void SocketTestQ::UDPReceivedData()
{
    QUdpSocket *socket = qobject_cast<QUdpSocket *>(sender()); // which client has sent data
    if (socket == 0)
        return;

    m_UDPByteArray->resize(socket->pendingDatagramSize());

    QHostAddress sender;
    quint16 senderPort;

    socket->readDatagram(m_UDPByteArray->data(), m_UDPByteArray->size(), &sender, &senderPort);

    if(ui->uiUdpRadioHex->isChecked())
    {
        ui->uiUdpLog->append(QString(m_UDPByteArray->toHex()));
    }
    else
    {
        ui->uiUdpLog->append(QString(*m_UDPByteArray));
    }

    m_UDPByteArray->remove(0, m_UDPByteArray->size() );
}

SocketTestQ::~SocketTestQ()
{
    delete ui;
    delete m_ServerByteArray;
    delete m_Server;
    delete m_ServerSocket;
    delete m_ClientByteArray;
}

void SocketTestQ::CheckSSLSupport()
{
    if (!QSslSocket::supportsSsl())
    {
        QMessageBox::information(0, "Secure Socket Client",
                                    "This system does not support OpenSSL.");

        ui->uiClientSecureCheck->setEnabled(false);
        ui->uiClientSecureCheck->setChecked(false);

        return;
    }

    // enryption files are not mandatory for an SSL/TLS client.
    s_qstrKeyFile = ui->uiKeyFileCli->text();
    s_qstrCertFile = ui->uiCertFileCli->text();

    switch (ui->uiCBProtocolCli->currentIndex())
    {
        default:
        case 0:
            s_eSSLProtocol = QSsl::AnyProtocol; // auto: SSLv2, SSLv3, or TLSv1.0
            break;
        case 1: // SSLv2
            s_eSSLProtocol = QSsl::SslV2;
            break;
        case 2: // SSLv3
            s_eSSLProtocol = QSsl::SslV3;
            break;
        case 3: // TLSv1.0
            s_eSSLProtocol = QSsl::TlsV1_0;
            break;
    }

    switch (ui->uiCBVerifyModeCli->currentIndex())
    {
        default:
        case 0:
            s_eSSLVerifyMode = QSslSocket::VerifyNone;
            break;
        case 1:
            s_eSSLVerifyMode = QSslSocket::QueryPeer;
            break;
        case 2:
            s_eSSLVerifyMode = QSslSocket::VerifyPeer;
            break;
        case 3:
            s_eSSLVerifyMode = QSslSocket::AutoVerifyPeer;
            break;
    }
}

void SocketTestQ::CheckSSLServerSetup()
{
    if (!QSslSocket::supportsSsl())
    {
        QMessageBox::information(0, "Secure Socket Server",
                                    "This system does not support OpenSSL.");

        ui->uiServerSecure->setEnabled(false);
        ui->uiServerSecure->setChecked(false);
        return;
    }

    // Check if the required files's paths are indicated and warn user if there's a problem...
    if (ui->uiKeyFile->text().isEmpty())
    {
        QMessageBox::information(0, "Secure Socket Server",
                                    "You didn't indicate private key's file path. Go to SSL Settings.");
        ui->uiServerSecure->setChecked(false);
        return;
    }
    CSSLServer::s_qstrKeyFile = ui->uiKeyFile->text();

    if (ui->uiCertFile->text().isEmpty())
    {
        QMessageBox::information(0, "Secure Socket Server",
                                    "You didn't indicate server's certificate file path. Go to SSL Settings.");
        ui->uiServerSecure->setChecked(false);
        return;
    }
    CSSLServer::s_qstrCertFile = ui->uiCertFile->text();

    switch (ui->uiCBProtocol->currentIndex())
    {
        default:
        case 0:
            /* The socket understands SSLv2, SSLv3, and TLSv1.0.
             * This value is used by QSslSocket only.*/
            CSSLServer::s_eSSLProtocol = QSsl::AnyProtocol;
            break;
        case 1: // SSLv2
            CSSLServer::s_eSSLProtocol = QSsl::SslV2;
            break;
        case 2: // SSLv3
            CSSLServer::s_eSSLProtocol = QSsl::SslV3;
            break;
        case 3: // TLSv1.0
            CSSLServer::s_eSSLProtocol = QSsl::TlsV1_0;
            break;
    }

    switch (ui->uiCBVerifyMode->currentIndex())
    {
        /* QSslSocket will not request a certificate from the peer.
         * You can set this mode if you are not interested in the identity of the other side of the connection.
         * The connection will still be encrypted, and your socket will still send its local certificate
         * to the peer if it's requested.
         */
        default:
        case 0:
            CSSLServer::s_eSSLVerifyMode = QSslSocket::VerifyNone;
            break;

        /* QSslSocket will request a certificate from the peer, but does not require this certificate to be valid.
         * This is useful when you want to display peer certificate details to the user without affecting
         * the actual SSL handshake.
         * This mode is the default for servers.
         */
        case 1:
            CSSLServer::s_eSSLVerifyMode = QSslSocket::QueryPeer;
            break;

        /* QSslSocket will request a certificate from the peer during the SSL handshake phase, and requires
         * that this certificate is valid. On failure, QSslSocket will emit the QSslSocket::sslErrors() signal.
         * This mode is the default for clients.
         */
        case 2:
            CSSLServer::s_eSSLVerifyMode = QSslSocket::VerifyPeer;
            break;

        /* QSslSocket will automatically use QueryPeer for server sockets and VerifyPeer for client sockets.
         */
        case 3:
            CSSLServer::s_eSSLVerifyMode = QSslSocket::AutoVerifyPeer;
            break;
    }
}

void SocketTestQ::PrivateKeyDialog()
{
    ui->uiKeyFile->setText(QFileDialog::getOpenFileName(this, tr("Choose a private key file"), QString(), "*.*"));
}

void SocketTestQ::CertDialog()
{
    ui->uiCertFile->setText(QFileDialog::getOpenFileName(this, tr("Choose a certificate file"), QString(), "*.*"));
}

void SocketTestQ::ProcessSSLReceivedData(QByteArray SSLByteArray)
{
    if(ui->uiServerRadioHex->isChecked())
    {
        ui->uiServerLog->append(QString(SSLByteArray.toHex()));
    }
    else
    {
        ui->uiServerLog->append(QString(SSLByteArray));
    }
}

void SocketTestQ::onSSLClientDisconnected()
{
    ui->uiServerSendMsgBtn->setEnabled(false);
    ui->uiServerSendFileBtn->setEnabled(false);
    ui->uiServerBrowseBtn->setEnabled(false);
    ui->uiServerDisconnectBtn->setEnabled(false);
    ui->uiServerGroupBoxConnection->setTitle( tr("Connected Client : < NONE >") );
    ui->uiServerLog->append(tr("SSL Client closed conection."));
}

void SocketTestQ::onNewSSLClient(QSslSocket* pSocket)
{
    ui->uiServerGroupBoxConnection->setTitle( tr("Connected SSL Client : < ") + (pSocket->peerAddress()).toString() +tr(" >") );
    ui->uiServerLog->append(tr("New SSL Client addr: ") + (pSocket->peerAddress()).toString());
    ui->uiServerSendMsgBtn->setEnabled(true);
    ui->uiServerSendFileBtn->setEnabled(true);
    ui->uiServerBrowseBtn->setEnabled(true);
    ui->uiServerDisconnectBtn->setEnabled(true);
}
