#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QNetworkInterface>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QDateTime>
#include <QDebug>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , portScanner(nullptr)
    , packetCapture(nullptr)
    , packetCounter(0)
    , isCapturing(false)
{
    ui->setupUi(this);
    setupUi();
}

MainWindow::~MainWindow()
{
    stopCapture();
    delete ui;
}

void MainWindow::setupUi()
{
    // Create filter widgets
    QWidget* filterWidget = new QWidget(this);
    QHBoxLayout* filterLayout = new QHBoxLayout(filterWidget);
    
    QLabel* filterLabel = new QLabel("Capture Filter:", filterWidget);
    filterEdit = new QLineEdit(filterWidget);
    filterEdit->setPlaceholderText("Enter capture filter (e.g., tcp port 5555)");
    
    QPushButton* applyFilterButton = new QPushButton("Apply", filterWidget);
    connect(applyFilterButton, &QPushButton::clicked,
            this, &MainWindow::applyFilter);

    filterLayout->addWidget(filterLabel);
    filterLayout->addWidget(filterEdit);
    filterLayout->addWidget(applyFilterButton);
    filterWidget->setLayout(filterLayout);

    // Add filter widget to main layout
    QVBoxLayout* mainLayout = qobject_cast<QVBoxLayout*>(ui->centralwidget->layout());
    if (mainLayout) {
        mainLayout->insertWidget(0, filterWidget);
    }

    // Connect signals
    connect(ui->startButton, &QPushButton::clicked,
            this, &MainWindow::toggleCapture);
    connect(ui->refreshPortsButton, &QPushButton::clicked,
            this, &MainWindow::scanPorts);
    connect(ui->protocolComboBox, &QComboBox::currentTextChanged,
            this, &MainWindow::protocolChanged);
    connect(ui->packetTable, &QTableWidget::cellClicked,
            this, &MainWindow::onPacketSelected);

    // Set table properties
    ui->packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->packetTable->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->packetTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->packetTable->horizontalHeader()->setStretchLastSection(true);

    // Set ports table properties
    ui->portsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->portsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->portsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->portsTable->horizontalHeader()->setStretchLastSection(true);

    // Initialize interface list
    refreshInterfaces();
}

void MainWindow::refreshInterfaces()
{
    ui->interfaceComboBox->clear();
    const QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();
    for(const auto& interface : interfaces) {
        if(interface.flags().testFlag(QNetworkInterface::IsUp) &&
           interface.flags().testFlag(QNetworkInterface::CanMulticast)) {
            ui->interfaceComboBox->addItem(interface.name());
        }
    }
}

void MainWindow::toggleCapture()
{
    if(!isCapturing) {
        startCapture();
    } else {
        stopCapture();
    }
}

void MainWindow::startCapture()
{
    if (packetCapture) {
        stopCapture();
    }

    if (ui->interfaceComboBox->currentText().isEmpty()) {
        QMessageBox::warning(this, "Error", "Please select a network interface");
        return;
    }

    packetCounter = 0;
    ui->packetTable->setRowCount(0);
    capturedPackets.clear();
    ui->packetDetailsText->clear();

    QString interface = ui->interfaceComboBox->currentText();
    QString protocol = ui->protocolComboBox->currentText();
    QString filter = filterEdit->text();
    
    if (filter.isEmpty()) {
        filter = "";  // default filter
    }

    packetCapture = new PacketCapture(interface, protocol, filter, this);
    connect(packetCapture, &PacketCapture::packetCaptured,
            this, &MainWindow::processPacket,
            Qt::QueuedConnection);
    packetCapture->start();

    ui->startButton->setText("Stop Capture");
    isCapturing = true;
}

void MainWindow::stopCapture()
{
    if (packetCapture) {
        packetCapture->stop();
        packetCapture->wait();
        delete packetCapture;
        packetCapture = nullptr;
    }
    ui->startButton->setText("Start Capture");
    isCapturing = false;
}

void MainWindow::processPacket(const PacketInfo& packet)
{
    packetCounter++;
    
    // Store the packet
    capturedPackets.append(packet);
    int row = capturedPackets.size() - 1;
    
    // Add to table
    ui->packetTable->insertRow(row);
    ui->packetTable->setItem(row, 0, new QTableWidgetItem(QString::number(packetCounter)));
    ui->packetTable->setItem(row, 1, new QTableWidgetItem(packet.timestamp));
    ui->packetTable->setItem(row, 2, new QTableWidgetItem(packet.sourceIP));
    ui->packetTable->setItem(row, 3, new QTableWidgetItem(packet.destIP));
    ui->packetTable->setItem(row, 4, new QTableWidgetItem(packet.protocol));
    ui->packetTable->setItem(row, 5, new QTableWidgetItem(QString::number(packet.length)));

    // Color the row based on protocol
    QColor rowColor;
    if (packet.protocol == "TCP") {
        rowColor = QColor(230, 240, 255);  // Light blue
    } else if (packet.protocol == "UDP") {
        rowColor = QColor(230, 255, 230);  // Light green
    } else if (packet.protocol == "ICMP") {
        rowColor = QColor(255, 230, 230);  // Light red
    }

    // Apply color to all cells in the row
    if (rowColor.isValid()) {
        for (int col = 0; col < ui->packetTable->columnCount(); ++col) {
            if (QTableWidgetItem* item = ui->packetTable->item(row, col)) {
                item->setBackground(rowColor);
            }
        }
    }

    // Auto-scroll if the last row was selected or no row is selected
    QModelIndex current = ui->packetTable->currentIndex();
    if (!current.isValid() || current.row() == row - 1) {
        ui->packetTable->scrollToBottom();
        updatePacketDetails(row);
        ui->packetTable->selectRow(row);
    }
}

void MainWindow::onPacketSelected(int row, int column)
{
    Q_UNUSED(column);
    updatePacketDetails(row);
}

void MainWindow::updatePacketDetails(int index)
{
    if (index >= 0 && index < capturedPackets.size()) {
        const PacketInfo& packet = capturedPackets[index];
        ui->packetDetailsText->setText(packet.details);
        
        // Scroll to top
        QTextCursor cursor = ui->packetDetailsText->textCursor();
        cursor.movePosition(QTextCursor::Start);
        ui->packetDetailsText->setTextCursor(cursor);
    } else {
        ui->packetDetailsText->clear();
    }
}

void MainWindow::scanPorts()
{
    ui->portsTable->setRowCount(0);

    QString protocol = ui->protocolComboBox->currentText();
    if(portScanner) {
        portScanner->stop();
        portScanner->wait();
        delete portScanner;
    }
    
    portScanner = new PortScanner(protocol, this);
    connect(portScanner, &PortScanner::portFound,
            this, &MainWindow::addPort);
    portScanner->start();
}

void MainWindow::protocolChanged(const QString& protocol)
{
    if(portScanner) {
        portScanner->stop();
        portScanner->wait();
        delete portScanner;
        portScanner = nullptr;
    }
    scanPorts();
}

void MainWindow::addPort(int port, const QString& protocol, 
                        const QString& state, const QString& service)
{
    int row = ui->portsTable->rowCount();
    ui->portsTable->insertRow(row);
    ui->portsTable->setItem(row, 0, new QTableWidgetItem(QString::number(port)));
    ui->portsTable->setItem(row, 1, new QTableWidgetItem(protocol));
    ui->portsTable->setItem(row, 2, new QTableWidgetItem(state));
    ui->portsTable->setItem(row, 3, new QTableWidgetItem(service));
}

void MainWindow::applyFilter()
{
    if (isCapturing) {
        stopCapture();
        startCapture();
    }
}