# Form implementation generated from reading ui file 'ui_win.ui'
#
# Created by: PyQt6 UI code generator 6.4.0
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets

import hexviewer
import listimgviewer


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1007, 670)
        MainWindow.setMinimumSize(QtCore.QSize(1007, 670))
        font = QtGui.QFont()
        font.setFamily("Courier New")
        font.setPointSize(10)
        MainWindow.setFont(font)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName("gridLayout")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.tab)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setContentsMargins(-1, -1, -1, 0)
        self.horizontalLayout.setSpacing(6)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.offsetInput = QtWidgets.QLineEdit(self.tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.offsetInput.sizePolicy().hasHeightForWidth())
        self.offsetInput.setSizePolicy(sizePolicy)
        self.offsetInput.setMinimumSize(QtCore.QSize(0, 26))
        self.offsetInput.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.offsetInput.setLocale(QtCore.QLocale(QtCore.QLocale.Language.English, QtCore.QLocale.Country.UnitedStates))
        self.offsetInput.setObjectName("offsetInput")
        self.horizontalLayout.addWidget(self.offsetInput)
        self.offsetOkbtn = QtWidgets.QPushButton(self.tab)
        self.offsetOkbtn.setMinimumSize(QtCore.QSize(0, 26))
        self.offsetOkbtn.setMaximumSize(QtCore.QSize(50, 16777215))
        self.offsetOkbtn.setObjectName("offsetOkbtn")
        self.horizontalLayout.addWidget(self.offsetOkbtn)
        self.gridLayout_2.addLayout(self.horizontalLayout, 6, 2, 1, 2)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.hexEditBtn = QtWidgets.QPushButton(self.tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.hexEditBtn.sizePolicy().hasHeightForWidth())
        self.hexEditBtn.setSizePolicy(sizePolicy)
        self.hexEditBtn.setMinimumSize(QtCore.QSize(70, 0))
        self.hexEditBtn.setObjectName("hexEditBtn")
        self.horizontalLayout_4.addWidget(self.hexEditBtn)
        self.hexEditDoneBtn = QtWidgets.QPushButton(self.tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.hexEditDoneBtn.sizePolicy().hasHeightForWidth())
        self.hexEditDoneBtn.setSizePolicy(sizePolicy)
        self.hexEditDoneBtn.setMinimumSize(QtCore.QSize(70, 0))
        self.hexEditDoneBtn.setObjectName("hexEditDoneBtn")
        self.horizontalLayout_4.addWidget(self.hexEditDoneBtn)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem1)
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem2)
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem3)
        self.gridLayout_2.addLayout(self.horizontalLayout_4, 0, 0, 1, 1)
        self.tabWidget2 = QtWidgets.QTabWidget(self.tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tabWidget2.sizePolicy().hasHeightForWidth())
        self.tabWidget2.setSizePolicy(sizePolicy)
        self.tabWidget2.setMinimumSize(QtCore.QSize(295, 0))
        self.tabWidget2.setMaximumSize(QtCore.QSize(16777215, 16777215))
        font = QtGui.QFont()
        font.setFamily("Courier New")
        font.setPointSize(10)
        self.tabWidget2.setFont(font)
        self.tabWidget2.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        self.tabWidget2.setLayoutDirection(QtCore.Qt.LayoutDirection.LeftToRight)
        self.tabWidget2.setObjectName("tabWidget2")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.gridLayout_3 = QtWidgets.QGridLayout(self.tab_3)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.status_img_name = QtWidgets.QLineEdit(self.tab_3)
        self.status_img_name.setMinimumSize(QtCore.QSize(0, 26))
        self.status_img_name.setMaximumSize(QtCore.QSize(16777215, 26))
        self.status_img_name.setObjectName("status_img_name")
        self.gridLayout_3.addWidget(self.status_img_name, 0, 1, 1, 1)
        self.label_8 = QtWidgets.QLabel(self.tab_3)
        self.label_8.setObjectName("label_8")
        self.gridLayout_3.addWidget(self.label_8, 5, 0, 1, 1)
        self.label_5 = QtWidgets.QLabel(self.tab_3)
        self.label_5.setObjectName("label_5")
        self.gridLayout_3.addWidget(self.label_5, 1, 0, 1, 1)
        self.label_4 = QtWidgets.QLabel(self.tab_3)
        self.label_4.setObjectName("label_4")
        self.gridLayout_3.addWidget(self.label_4, 0, 0, 1, 1)
        self.label_7 = QtWidgets.QLabel(self.tab_3)
        self.label_7.setObjectName("label_7")
        self.gridLayout_3.addWidget(self.label_7, 4, 0, 1, 1)
        self.label_6 = QtWidgets.QLabel(self.tab_3)
        self.label_6.setObjectName("label_6")
        self.gridLayout_3.addWidget(self.label_6, 2, 0, 1, 1)
        self.status_img_base = QtWidgets.QTextBrowser(self.tab_3)
        self.status_img_base.setMaximumSize(QtCore.QSize(16777215, 26))
        self.status_img_base.setObjectName("status_img_base")
        self.gridLayout_3.addWidget(self.status_img_base, 1, 1, 1, 1)
        self.status_current = QtWidgets.QTextBrowser(self.tab_3)
        self.status_current.setMaximumSize(QtCore.QSize(16777215, 26))
        self.status_current.setObjectName("status_current")
        self.gridLayout_3.addWidget(self.status_current, 2, 1, 1, 1)
        self.status_end = QtWidgets.QTextBrowser(self.tab_3)
        self.status_end.setMaximumSize(QtCore.QSize(16777215, 26))
        self.status_end.setObjectName("status_end")
        self.gridLayout_3.addWidget(self.status_end, 4, 1, 1, 1)
        self.status_size = QtWidgets.QTextBrowser(self.tab_3)
        self.status_size.setMaximumSize(QtCore.QSize(16777215, 26))
        self.status_size.setObjectName("status_size")
        self.gridLayout_3.addWidget(self.status_size, 5, 1, 1, 1)
        self.label_9 = QtWidgets.QLabel(self.tab_3)
        self.label_9.setObjectName("label_9")
        self.gridLayout_3.addWidget(self.label_9, 6, 0, 1, 1)
        self.status_path = QtWidgets.QTextBrowser(self.tab_3)
        self.status_path.setObjectName("status_path")
        self.gridLayout_3.addWidget(self.status_path, 6, 1, 1, 1)
        self.tabWidget2.addTab(self.tab_3, "")
        self.tab_4 = QtWidgets.QWidget()
        self.tab_4.setObjectName("tab_4")
        self.gridLayout_4 = QtWidgets.QGridLayout(self.tab_4)
        self.gridLayout_4.setObjectName("gridLayout_4")
        self.memDumpModuleName = QtWidgets.QLineEdit(self.tab_4)
        self.memDumpModuleName.setObjectName("memDumpModuleName")
        self.gridLayout_4.addWidget(self.memDumpModuleName, 2, 0, 1, 1)
        # self.listImgViewer = QtWidgets.QTextBrowser(self.tab_4)
        self.listImgViewer = listimgviewer.ListImgViewerClass(self.tab_4)
        self.listImgViewer.setMinimumSize(QtCore.QSize(0, 0))
        self.listImgViewer.setMaximumSize(QtCore.QSize(16777215, 500))
        self.listImgViewer.setObjectName("listImgViewer")
        self.gridLayout_4.addWidget(self.listImgViewer, 0, 0, 1, 2)
        self.memDumpBtn = QtWidgets.QPushButton(self.tab_4)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.memDumpBtn.sizePolicy().hasHeightForWidth())
        self.memDumpBtn.setSizePolicy(sizePolicy)
        self.memDumpBtn.setMinimumSize(QtCore.QSize(50, 0))
        self.memDumpBtn.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        self.memDumpBtn.setObjectName("memDumpBtn")
        self.gridLayout_4.addWidget(self.memDumpBtn, 2, 1, 1, 1)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.label_12 = QtWidgets.QLabel(self.tab_4)
        self.label_12.setMaximumSize(QtCore.QSize(180, 16777215))
        self.label_12.setAlignment(QtCore.Qt.AlignmentFlag.AlignLeading|QtCore.Qt.AlignmentFlag.AlignLeft|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.label_12.setObjectName("label_12")
        self.horizontalLayout_5.addWidget(self.label_12)
        self.unityCheckBox = QtWidgets.QCheckBox(self.tab_4)
        self.unityCheckBox.setMaximumSize(QtCore.QSize(68, 16777215))
        self.unityCheckBox.setObjectName("unityCheckBox")
        self.horizontalLayout_5.addWidget(self.unityCheckBox)
        self.gridLayout_4.addLayout(self.horizontalLayout_5, 1, 0, 1, 2)
        self.tabWidget2.addTab(self.tab_4, "")
        self.tab_5 = QtWidgets.QWidget()
        self.tab_5.setObjectName("tab_5")
        self.gridLayout_5 = QtWidgets.QGridLayout(self.tab_5)
        self.gridLayout_5.setObjectName("gridLayout_5")
        self.memScanPatternTypeCheckBox = QtWidgets.QCheckBox(self.tab_5)
        self.memScanPatternTypeCheckBox.setMaximumSize(QtCore.QSize(16777215, 15))
        self.memScanPatternTypeCheckBox.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        self.memScanPatternTypeCheckBox.setObjectName("memScanPatternTypeCheckBox")
        self.gridLayout_5.addWidget(self.memScanPatternTypeCheckBox, 1, 3, 1, 1)
        self.label_10 = QtWidgets.QLabel(self.tab_5)
        self.label_10.setObjectName("label_10")
        self.gridLayout_5.addWidget(self.label_10, 1, 0, 1, 2)
        self.memSearchFoundCount = QtWidgets.QLabel(self.tab_5)
        self.memSearchFoundCount.setMinimumSize(QtCore.QSize(0, 0))
        self.memSearchFoundCount.setMaximumSize(QtCore.QSize(16777215, 10))
        self.memSearchFoundCount.setText("")
        self.memSearchFoundCount.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.memSearchFoundCount.setObjectName("memSearchFoundCount")
        self.gridLayout_5.addWidget(self.memSearchFoundCount, 6, 2, 1, 3)
        self.memSearchReplaceCheckBox = QtWidgets.QCheckBox(self.tab_5)
        self.memSearchReplaceCheckBox.setMaximumSize(QtCore.QSize(16777215, 15))
        self.memSearchReplaceCheckBox.setObjectName("memSearchReplaceCheckBox")
        self.gridLayout_5.addWidget(self.memSearchReplaceCheckBox, 1, 4, 1, 1)
        self.searchMemSearchResult = QtWidgets.QLineEdit(self.tab_5)
        self.searchMemSearchResult.setText("")
        self.searchMemSearchResult.setObjectName("searchMemSearchResult")
        self.gridLayout_5.addWidget(self.searchMemSearchResult, 9, 0, 1, 5)
        spacerItem4 = QtWidgets.QSpacerItem(50, 10, QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum)
        self.gridLayout_5.addItem(spacerItem4, 1, 2, 1, 1)
        self.memReplacePattern = QtWidgets.QTextEdit(self.tab_5)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(1)
        sizePolicy.setHeightForWidth(self.memReplacePattern.sizePolicy().hasHeightForWidth())
        self.memReplacePattern.setSizePolicy(sizePolicy)
        self.memReplacePattern.setMinimumSize(QtCore.QSize(190, 26))
        self.memReplacePattern.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.memReplacePattern.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self.memReplacePattern.setTabChangesFocus(True)
        self.memReplacePattern.setAcceptRichText(False)
        self.memReplacePattern.setObjectName("memReplacePattern")
        self.gridLayout_5.addWidget(self.memReplacePattern, 3, 0, 1, 4)
        self.label_11 = QtWidgets.QLabel(self.tab_5)
        self.label_11.setMinimumSize(QtCore.QSize(0, 0))
        self.label_11.setMaximumSize(QtCore.QSize(16777215, 10))
        self.label_11.setObjectName("label_11")
        self.gridLayout_5.addWidget(self.label_11, 6, 0, 1, 2)
        # self.memSearchResult = QtWidgets.QTextBrowser(self.tab_5)
        self.memSearchResult = listimgviewer.MemSearchResultBrowserClass(self.tab_5)
        self.memSearchResult.setMinimumSize(QtCore.QSize(0, 0))
        self.memSearchResult.setObjectName("memSearchResult")
        self.gridLayout_5.addWidget(self.memSearchResult, 7, 0, 2, 5)
        self.memSearchPattern = QtWidgets.QTextEdit(self.tab_5)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(1)
        sizePolicy.setHeightForWidth(self.memSearchPattern.sizePolicy().hasHeightForWidth())
        self.memSearchPattern.setSizePolicy(sizePolicy)
        self.memSearchPattern.setMinimumSize(QtCore.QSize(190, 26))
        self.memSearchPattern.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self.memSearchPattern.setTabChangesFocus(True)
        self.memSearchPattern.setAcceptRichText(False)
        self.memSearchPattern.setObjectName("memSearchPattern")
        self.gridLayout_5.addWidget(self.memSearchPattern, 2, 0, 1, 4)
        self.memReplaceBtn = QtWidgets.QPushButton(self.tab_5)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.memReplaceBtn.sizePolicy().hasHeightForWidth())
        self.memReplaceBtn.setSizePolicy(sizePolicy)
        self.memReplaceBtn.setMinimumSize(QtCore.QSize(50, 26))
        self.memReplaceBtn.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.memReplaceBtn.setObjectName("memReplaceBtn")
        self.gridLayout_5.addWidget(self.memReplaceBtn, 3, 4, 1, 1)
        self.memSearchBtn = QtWidgets.QPushButton(self.tab_5)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.memSearchBtn.sizePolicy().hasHeightForWidth())
        self.memSearchBtn.setSizePolicy(sizePolicy)
        self.memSearchBtn.setMinimumSize(QtCore.QSize(50, 26))
        self.memSearchBtn.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.memSearchBtn.setObjectName("memSearchBtn")
        self.gridLayout_5.addWidget(self.memSearchBtn, 2, 4, 1, 1)
        self.progressBar = QtWidgets.QProgressBar(self.tab_5)
        self.progressBar.setMinimumSize(QtCore.QSize(253, 0))
        self.progressBar.setMaximumSize(QtCore.QSize(16777215, 15))
        self.progressBar.setProperty("value", 0)
        self.progressBar.setInvertedAppearance(False)
        self.progressBar.setObjectName("progressBar")
        self.gridLayout_5.addWidget(self.progressBar, 5, 0, 1, 4)
        self.memSearchTargetImgInput = QtWidgets.QLineEdit(self.tab_5)
        self.memSearchTargetImgInput.setEnabled(False)
        self.memSearchTargetImgInput.setMinimumSize(QtCore.QSize(0, 26))
        self.memSearchTargetImgInput.setObjectName("memSearchTargetImgInput")
        self.gridLayout_5.addWidget(self.memSearchTargetImgInput, 0, 0, 1, 4)
        self.memSearchTargetImgCheckBox = QtWidgets.QCheckBox(self.tab_5)
        self.memSearchTargetImgCheckBox.setMaximumSize(QtCore.QSize(16777215, 15))
        self.memSearchTargetImgCheckBox.setObjectName("memSearchTargetImgCheckBox")
        self.gridLayout_5.addWidget(self.memSearchTargetImgCheckBox, 0, 4, 1, 1)
        self.tabWidget2.addTab(self.tab_5, "")
        self.gridLayout_2.addWidget(self.tabWidget2, 9, 2, 11, 2)
        self.label_3 = QtWidgets.QLabel(self.tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_3.sizePolicy().hasHeightForWidth())
        self.label_3.setSizePolicy(sizePolicy)
        self.label_3.setScaledContents(False)
        self.label_3.setWordWrap(False)
        self.label_3.setIndent(21)
        self.label_3.setObjectName("label_3")
        self.gridLayout_2.addWidget(self.label_3, 2, 0, 1, 2)
        self.label = QtWidgets.QLabel(self.tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label.sizePolicy().hasHeightForWidth())
        self.label.setSizePolicy(sizePolicy)
        self.label.setMaximumSize(QtCore.QSize(16777215, 10))
        self.label.setObjectName("label")
        self.gridLayout_2.addWidget(self.label, 5, 2, 1, 1)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setSizeConstraint(QtWidgets.QLayout.SizeConstraint.SetMaximumSize)
        self.horizontalLayout_2.setContentsMargins(-1, -1, -1, 0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.addrInput = QtWidgets.QLineEdit(self.tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.addrInput.sizePolicy().hasHeightForWidth())
        self.addrInput.setSizePolicy(sizePolicy)
        self.addrInput.setMinimumSize(QtCore.QSize(0, 26))
        self.addrInput.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.addrInput.setObjectName("addrInput")
        self.horizontalLayout_2.addWidget(self.addrInput)
        self.addrBtn = QtWidgets.QPushButton(self.tab)
        self.addrBtn.setMinimumSize(QtCore.QSize(0, 26))
        self.addrBtn.setMaximumSize(QtCore.QSize(50, 16777215))
        self.addrBtn.setObjectName("addrBtn")
        self.horizontalLayout_2.addWidget(self.addrBtn)
        self.gridLayout_2.addLayout(self.horizontalLayout_2, 8, 2, 1, 2)
        # self.hexViewer = QtWidgets.QTextEdit(self.tab)
        self.hexViewer = hexviewer.HexViewerClass(self.tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.hexViewer.sizePolicy().hasHeightForWidth())
        self.hexViewer.setSizePolicy(sizePolicy)
        self.hexViewer.setMinimumSize(QtCore.QSize(630, 0))
        self.hexViewer.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.hexViewer.setLocale(QtCore.QLocale(QtCore.QLocale.Language.English, QtCore.QLocale.Country.UnitedStates))
        self.hexViewer.setInputMethodHints(QtCore.Qt.InputMethodHint.ImhMultiLine)
        self.hexViewer.setReadOnly(True)
        self.hexViewer.setOverwriteMode(True)
        self.hexViewer.setAcceptRichText(True)
        # self.hexViewer.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.NoTextInteraction)
        self.hexViewer.setObjectName("hexViewer")
        self.gridLayout_2.addWidget(self.hexViewer, 4, 0, 16, 2)
        self.label_2 = QtWidgets.QLabel(self.tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_2.sizePolicy().hasHeightForWidth())
        self.label_2.setSizePolicy(sizePolicy)
        self.label_2.setMaximumSize(QtCore.QSize(16777215, 10))
        self.label_2.setObjectName("label_2")
        self.gridLayout_2.addWidget(self.label_2, 7, 2, 1, 1)
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.attachTypeCheckBox = QtWidgets.QCheckBox(self.tab)
        self.attachTypeCheckBox.setMaximumSize(QtCore.QSize(110, 16777215))
        self.attachTypeCheckBox.setObjectName("attachTypeCheckBox")
        self.horizontalLayout_6.addWidget(self.attachTypeCheckBox)
        self.spawnModeCheckBox = QtWidgets.QCheckBox(self.tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.spawnModeCheckBox.sizePolicy().hasHeightForWidth())
        self.spawnModeCheckBox.setSizePolicy(sizePolicy)
        self.spawnModeCheckBox.setMinimumSize(QtCore.QSize(0, 0))
        self.spawnModeCheckBox.setMaximumSize(QtCore.QSize(110, 16777215))
        self.spawnModeCheckBox.setObjectName("spawnModeCheckBox")
        self.horizontalLayout_6.addWidget(self.spawnModeCheckBox)
        self.gridLayout_2.addLayout(self.horizontalLayout_6, 2, 2, 1, 1)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.attachBtn = QtWidgets.QPushButton(self.tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.attachBtn.sizePolicy().hasHeightForWidth())
        self.attachBtn.setSizePolicy(sizePolicy)
        self.attachBtn.setMinimumSize(QtCore.QSize(110, 0))
        self.attachBtn.setFocusPolicy(QtCore.Qt.FocusPolicy.TabFocus)
        self.attachBtn.setObjectName("attachBtn")
        self.horizontalLayout_3.addWidget(self.attachBtn)
        self.detachBtn = QtWidgets.QPushButton(self.tab)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.detachBtn.sizePolicy().hasHeightForWidth())
        self.detachBtn.setSizePolicy(sizePolicy)
        self.detachBtn.setMinimumSize(QtCore.QSize(110, 0))
        self.detachBtn.setObjectName("detachBtn")
        self.horizontalLayout_3.addWidget(self.detachBtn)
        self.gridLayout_2.addLayout(self.horizontalLayout_3, 4, 2, 1, 2)
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.listPIDCheckBox = QtWidgets.QCheckBox(self.tab)
        self.listPIDCheckBox.setMinimumSize(QtCore.QSize(200, 0))
        self.listPIDCheckBox.setMaximumSize(QtCore.QSize(110, 16777215))
        self.listPIDCheckBox.setObjectName("listPIDCheckBox")
        self.horizontalLayout_7.addWidget(self.listPIDCheckBox)
        self.gridLayout_2.addLayout(self.horizontalLayout_7, 0, 2, 1, 1)
        self.label.raise_()
        self.tabWidget2.raise_()
        self.label_2.raise_()
        self.label_3.raise_()
        self.hexViewer.raise_()
        self.tabWidget.addTab(self.tab, "")
        self.gridLayout.addWidget(self.tabWidget, 0, 0, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        self.tabWidget2.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MLViewer"))
        self.offsetOkbtn.setText(_translate("MainWindow", "GO"))
        self.hexEditBtn.setText(_translate("MainWindow", "HexEdit"))
        self.hexEditDoneBtn.setText(_translate("MainWindow", "Done"))
        self.label_8.setText(_translate("MainWindow", "Size"))
        self.label_5.setText(_translate("MainWindow", "Base"))
        self.label_4.setText(_translate("MainWindow", "Name"))
        self.label_7.setText(_translate("MainWindow", "End"))
        self.label_6.setText(_translate("MainWindow", "Current"))
        self.label_9.setText(_translate("MainWindow", "Path"))
        self.tabWidget2.setTabText(self.tabWidget2.indexOf(self.tab_3), _translate("MainWindow", "Status"))
        self.memDumpBtn.setText(_translate("MainWindow", "Dump"))
        self.label_12.setText(_translate("MainWindow", "Unity? Check & Dump"))
        self.unityCheckBox.setText(_translate("MainWindow", "Unity"))
        self.tabWidget2.setTabText(self.tabWidget2.indexOf(self.tab_4), _translate("MainWindow", "List IMG"))
        self.memScanPatternTypeCheckBox.setText(_translate("MainWindow", "Str"))
        self.label_10.setText(_translate("MainWindow", "Pattern"))
        self.memSearchReplaceCheckBox.setText(_translate("MainWindow", "Rep"))
        self.label_11.setText(_translate("MainWindow", "Result"))
        self.memReplaceBtn.setText(_translate("MainWindow", "REP"))
        self.memSearchBtn.setText(_translate("MainWindow", "GO"))
        self.memSearchTargetImgCheckBox.setText(_translate("MainWindow", "Img"))
        self.tabWidget2.setTabText(self.tabWidget2.indexOf(self.tab_5), _translate("MainWindow", "Search"))
        self.label_3.setText(_translate("MainWindow", "ADDRESS   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF"))
        self.label.setText(_translate("MainWindow", "Offset"))
        self.addrBtn.setText(_translate("MainWindow", "GO"))
        self.hexViewer.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"hr { height: 1px; border-width: 0; }\n"
"li.unchecked::marker { content: \"\\2610\"; }\n"
"li.checked::marker { content: \"\\2612\"; }\n"
"</style></head><body style=\" font-family:\'Courier New\'; font-size:10pt; font-weight:400; font-style:normal;\">\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:13pt;\"><br /></p></body></html>"))
        self.label_2.setText(_translate("MainWindow", "Address"))
        self.attachTypeCheckBox.setText(_translate("MainWindow", "Remote"))
        self.spawnModeCheckBox.setText(_translate("MainWindow", "Spawn"))
        self.attachBtn.setText(_translate("MainWindow", "Attach"))
        self.detachBtn.setText(_translate("MainWindow", "Detach"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("MainWindow", "Viewer"))
