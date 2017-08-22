package vn.softdreams.hnx.nativehost.gui;

/*
 * TokenManagement.java
 *
 * Created on Oct 14, 2011, 10:09:59 AM
 */

import vn.softdreams.hnx.nativehost.main.Main;

import java.awt.Dimension;
import java.awt.HeadlessException;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.GroupLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.LayoutStyle;
import javax.swing.ListSelectionModel;
import javax.swing.WindowConstants;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;

/**
 * @author tamdx
 */
public class SelectCertificate extends JDialog {

    private static org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(SelectCertificate.class);

    private JButton okButton;
    private JButton cancelButton;
    private JLabel headerLabel;
    private JScrollPane jScrollPane1;
    private JTable certificateTable;
    private List listCertificate = new ArrayList();
    private List<X509Certificate> certs = new ArrayList<>();
    private X509Certificate selectedCert;
    private int selectedIndex;

    public SelectCertificate(JFrame parent, boolean modal, List<X509Certificate> _certs) {
        super(parent, modal);
        this.certs = _certs;
        initComponent();
    }

    public X509Certificate getSelectedCert() {
        return selectedCert;
    }

    public int getSelectedIndex() {
        return selectedIndex;
    }

    private void loadData() {
        if (certs.isEmpty()) return;
        logger.info("Load Data - Certs size: " + certs.size());
        String[][] obj = new String[certs.size()][3];
        for (int i = 0; i < certs.size(); i++) {
            obj[i][0] = certs.get(i).getSubjectDN().getName();
            obj[i][1] = certs.get(i).getIssuerDN().getName();
            obj[i][2] = certs.get(i).getNotAfter().toString();

        }
        certificateTable.setModel(new DefaultTableModel(
                obj,
                new String[]{
                        "Cấp cho", "Cấp bởi", "Hết hạn"
                }) {

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return false;
            }
        });
    }

    private void initComponent() throws HeadlessException {
        this.setTitle("Lựa chọn chứng thư");
        setAlwaysOnTop(true);
        headerLabel = new JLabel();
        jScrollPane1 = new JScrollPane();
        certificateTable = new JTable();
        okButton = new JButton();
        cancelButton = new JButton();

        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);

        loadData();
        certificateTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        certificateTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {

            public void valueChanged(ListSelectionEvent e) {
                if (certificateTable.getSelectedRow() >= 0 && certificateTable.getSelectedRow() < certs.size()) {
                    selectedCert = certs.get(certificateTable.getSelectedRow());
                    selectedIndex = certificateTable.getSelectedRow();
                } else {
                    selectedCert = null;
                }
            }
        });
        jScrollPane1.setViewportView(certificateTable);

        okButton.setText("Đồng ý");
        okButton.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent evt) {
                if (selectedCert == null) {
                    JOptionPane.showMessageDialog(null, "Bạn chưa chọn chứng thư", "Lỗi chọn chứng thư",
                            JOptionPane.ERROR_MESSAGE);
                } else {
                    setVisible(false);
                }
            }
        });

        cancelButton.setText("Hủy bỏ");
        cancelButton.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent evt) {
                certificateTable.clearSelection();
                setVisible(false);
            }
        });

        GroupLayout layout = new GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING).addGroup(layout.
                        createSequentialGroup().addContainerGap().addGroup(layout.createParallelGroup(
                        GroupLayout.Alignment.LEADING).addGroup(layout.createSequentialGroup().addGroup(layout.
                        createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(headerLabel,
                        GroupLayout.DEFAULT_SIZE, 430, Short.MAX_VALUE).addComponent(jScrollPane1,
                        GroupLayout.Alignment.TRAILING, GroupLayout.PREFERRED_SIZE, 425, GroupLayout.PREFERRED_SIZE)).
                        addContainerGap()).addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup().
                        addComponent(okButton).addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED).addComponent(
                        cancelButton).addGap(12, 12, 12)))));
        layout.setVerticalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING).addGroup(layout.
                        createSequentialGroup().addComponent(headerLabel).addPreferredGap(
                        LayoutStyle.ComponentPlacement.RELATED).addComponent(jScrollPane1, GroupLayout.PREFERRED_SIZE,
                        90, GroupLayout.PREFERRED_SIZE).addPreferredGap(LayoutStyle.ComponentPlacement.RELATED).
                        addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(okButton).
                                addComponent(cancelButton)).addContainerGap(15, Short.MAX_VALUE)));

        pack();

        Toolkit toolkit = Toolkit.getDefaultToolkit();
        Dimension dim = toolkit.getScreenSize();
        this.setLocation((int) ((dim.getWidth() - this.getWidth()) / 2), (int) ((dim.getHeight() - this.
                getHeight()) / 2));

        this.addWindowListener(new WindowAdapter() {

            public void windowClosing(WindowEvent e) {
                setVisible(false);
            }
        });
    }
}
