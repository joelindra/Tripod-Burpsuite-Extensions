package burp;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener {

    private IBurpExtenderCallbacks callbacks;
    private JTabbedPane mainTabbedPane;
    private TripodPanel tripodPanel;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private boolean isUnloading = false;

    private static class TeeOutputStream extends OutputStream {
        private final OutputStream streamOne;
        private final OutputStream streamTwo;

        public TeeOutputStream(OutputStream streamOne, OutputStream streamTwo) {
            this.streamOne = streamOne;
            this.streamTwo = streamTwo;
        }

        @Override
        public void write(int b) throws IOException {
            streamOne.write(b);
            streamTwo.write(b);
        }

        @Override
        public void flush() throws IOException {
            streamOne.flush();
            streamTwo.flush();
        }

        @Override
        public void close() throws IOException {
            try {
                streamOne.close();
            } finally {
                streamTwo.close();
            }
        }
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        OutputStream dualErrorStream = new TeeOutputStream(callbacks.getStderr(), System.err);
        this.stderr = new PrintWriter(dualErrorStream, true);

        callbacks.setExtensionName("Tripod");

        // Initialize Tripod panel
        tripodPanel = new TripodPanel(callbacks);

        callbacks.registerContextMenuFactory(this);
        callbacks.registerExtensionStateListener(this);

        SwingUtilities.invokeLater(() -> {
            mainTabbedPane = new JTabbedPane();
            mainTabbedPane.addTab("Tripod", tripodPanel);

            callbacks.addSuiteTab(this);
            loadAllSettings();
            stdout.println("Tripod loaded successfully!");
        });
    }

    private void saveAllSettings(boolean showMessage) {
        // NOTE: This is disabled because TripodPanel does not have a saveSettings() method.
        // You will need to implement this method in TripodPanel.java to enable saving.
        /*
        try {
            if (tripodPanel != null) {
                tripodPanel.saveSettings(showMessage); // This line caused the error
            }
            if (showMessage) {
                stdout.println("Tripod: Tripod settings saved successfully!");
            }
        } catch (Exception e) {
            stderr.println("Error saving Tripod settings: " + e.getMessage());
            e.printStackTrace(stderr);
        }
        */
    }

    private void loadAllSettings() {
        // NOTE: This is disabled because TripodPanel does not have a loadSettings() method.
        // You will need to implement this method in TripodPanel.java to enable loading settings.
        /*
        try {
            if (tripodPanel != null) {
                tripodPanel.loadSettings(); // This line caused the error
            }
            stdout.println("Tripod: Tripod settings loaded successfully!");
        } catch (Exception e) {
            stderr.println("Error loading Tripod settings: " + e.getMessage());
            e.printStackTrace(stderr);
        }
        */
    }

    @Override
    public void extensionUnloaded() {
        stdout.println("Tripod extension unloading.");
        isUnloading = true;
        saveAllSettings(false);
    }

    @Override
    public String getTabCaption() {
        return "Tripod";
    }

    @Override
    public Component getUiComponent() {
        return mainTabbedPane;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        // NOTE: The context menu is disabled because TripodPanel does not have an addEntry() method.
        // To enable the "Send to Tripod" menu, you must implement a public method in TripodPanel
        // that can accept a request (e.g., public void addEntry(IHttpRequestResponse requestResponse, int toolFlag)).

        /*
        List<JMenuItem> menu = new ArrayList<>();
        JMenu topMenu = new JMenu("Send to Tripod");

        JMenuItem sendToTripod = new JMenuItem("Send to Tripod");
        sendToTripod.addActionListener(e -> {
            int toolFlag = invocation.getToolFlag();
            for (IHttpRequestResponse requestResponse : invocation.getSelectedMessages()) {
                tripodPanel.addEntry(requestResponse, toolFlag); // This line caused the error
            }
            mainTabbedPane.setSelectedComponent(tripodPanel);
        });
        topMenu.add(sendToTripod);
        menu.add(topMenu);
        return menu;
        */

        // Return an empty list to prevent any menu from appearing.
        return new ArrayList<>();
    }
}