#include "SocketTestQ.h"
#include "ui_SocketTestQ.h"

#define MAX_HOSTNAME_LENGTH     255
#define my_delete(x) {delete x; x = 0;}

SocketTestQ::SocketTestQ(QWidget *parent) :
    QWidget(parent), ui(new Ui::SocketTestQ)
{
    // ************** Miscellaneous
    // **************

    ui->setupUi(this);
    setFixedSize(geometry().width(),geometry().height());
    //setWindowTitle(tr("SocketTestQ v 1.0.0"));

    // ************** Server
    // **************

    m_Server = new QTcpServer(this);
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

    // Connection between signals and slots of non-gui elements (network communication)
    connect(m_Server, SIGNAL(newConnection()), this, SLOT(NewClient()));

    // ************** Client
    // ************** autoconnect has been used for a few client's widgets

    m_ServerSocket = new QTcpSocket(this);
    m_ClientByteArray = new QByteArray();

    // Connection between signals and slots of non-gui elements (network communication)
    connect(m_ServerSocket, SIGNAL(readyRead()), this, SLOT(ClientReceivedData()));
    connect(m_ServerSocket, SIGNAL(connected()), this, SLOT(ClientConnected()));
    connect(m_ServerSocket, SIGNAL(disconnected()), this, SLOT(ClientDisconnected()));
    connect(m_ServerSocket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(SocketError(QAbstractSocket::SocketError)));

    // Connection between signals and slots of buttons
    connect(ui->uiClientPortListBtn, SIGNAL(clicked()), this, SLOT(ShowTCPPortList()));
    connect(ui->uiClientRadioHex, SIGNAL(clicked()), this, SLOT(WarnHex()));
    connect(ui->uiClientBrowseBtn, SIGNAL(clicked()), this, SLOT(ClientOpenFileNameDialog()));
    connect(ui->uiClientSendFileBtn, SIGNAL(clicked()), this, SLOT(ClientSendFile()));
    connect(ui->uiClientSaveLogBtn, SIGNAL(clicked()), this, SLOT(ClientSaveLogFile()));
    connect(ui->uiClientClearLogBtn, SIGNAL(clicked()), this, SLOT(ClientClearLogFile()));

    connect(ui->uiClientSecureCheck, SIGNAL(clicked()), this, SLOT(WarnSecure()));
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
    if(m_Server->isListening())
    {
        m_Server->close();
        ui->uiServerListenBtn->setText( tr("Start Listening") );
        ui->uiServerLog->append(tr("Server stopped"));
        return;
    }

    if((ui->uiServerIP->text()).length() <= MAX_HOSTNAME_LENGTH )
    {
        QHostAddress ServerAddress(ui->uiServerIP->text()); // if this ctor is not explicit, we can put the text directly on listen()

        if ( !m_Server->listen(ServerAddress, ui->uiServerPort->value() ) )
        {
            QMessageBox::critical(this, tr("Server Error"), tr("Server couldn't start. Reason :<br />") + m_Server->errorString());
        }
        else
        {
            ui->uiServerListenBtn->setText( tr("Stop Listening") );
            ui->uiServerLog->append(tr("Server Started\r\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
        }
    }
    else
    {
        QMessageBox::critical(this, tr("TCP Server Error"), tr("IP address / hostname is too long !"));
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
    if(m_ClientSocket)
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

    m_ClientSocket->write(packet);

    ui->uiServerLog->append("S: " + ui->uiServerMsg->text());
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

        m_ClientSocket->write(packet);

        file.close();
        ui->uiServerLog->append("S: File was sent to connected client.");
    }
}

/******** Client ********/

// Connection attempt to a server
void SocketTestQ::on_uiClientConnectBtn_clicked()
{
    if(m_ServerSocket->isOpen())
    {
        m_ServerSocket->close();
        return;
    }

    ui->uiClientLog->append(tr("<em>Attempting to connect...</em>"));

    m_ServerSocket->abort(); // disable previous connections if they exist
    m_ServerSocket->connectToHost(ui->uiClientDstIP->text(), ui->uiClientDstPort->value()); // connection to the requested server
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

    ui->uiClientLog->append("S: " + ui->uiClientMsg->text());
    ui->uiClientMsg->clear();
    ui->uiClientMsg->setFocus(); // set the focus inside it
}

// Pressing "Enter" has the same effect than clicking on "Send" button
void SocketTestQ::on_uiClientMsg_returnPressed()
{
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
        ui->uiClientLog->append("S: File was sent to server.");
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

    ui->uiUdpLog->append("S: " + ui->uiUdpMsg->text());
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
        ui->uiUdpLog->append("S: File was sent.");
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

void SocketTestQ::WarnSecure()
{
    QMessageBox::information(this, tr("Secure Mode"), tr("Will be available in the next version !"));
}
