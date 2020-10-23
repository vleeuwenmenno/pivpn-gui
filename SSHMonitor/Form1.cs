using Renci.SshNet;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Net.Sockets;
using System.Threading;
using System.Windows.Forms;
using Renci.SshNet.Common;
using System.IO;
using Newtonsoft.Json;
using System.Text.RegularExpressions;

namespace SSHMonitor
{
    public partial class Form1 : Form
    {
        Thread testThread;
        public List<ConnectionInfo> connections;
        ConnectionInfo activeConnection;

        public Form1()
        {
            InitializeComponent();

            if (File.Exists(Environment.CurrentDirectory + "/connections.json"))
                connections = JsonConvert.DeserializeObject<List<ConnectionInfo>>(File.ReadAllText(Environment.CurrentDirectory + "/connections.json"));
            
            else
                connections = new List<ConnectionInfo>();
            
            wireGuardListView.Items.Add(new ListViewItem("Loading ..."));
        }

        private void addConnBtn_Click(object sender, EventArgs e)
        {
            addConnPanel.Visible = true;
            editConnBtn.Visible = false;

            addConnBtn.Visible = !addConnPanel.Visible;
            basePanel.Visible = !basePanel.Visible;
        }

        private void button3_Click(object sender, EventArgs e)
        {
            editConnBtn.Visible = true;
            addConnPanel.Visible = false;
            addConnBtn.Visible = !addConnPanel.Visible;
            basePanel.Visible = !basePanel.Visible;

            if (testThread != null)
                testThread = null;
        }

        public void enableUI(bool disableSave = false, bool enable = true)
        {
            inputPanel.Enabled = enable;
            testBtn.Enabled = enable;
            saveBtn.Enabled = !disableSave;
        }

        public void ReloadUI()
        {
            int y = 0;
            int x = 0;

            int height = 72;
            int width = 272;

            int cols = 5;

            foreach (ConnectionInfo connInfo in connections)
            {
                Panel p = new Panel();

                Label serverName = new Label();
                Label serverDetail = new Label();
                Label statusPoint = new Label();

                LinkLabel puttyLabel = new LinkLabel();
                LinkLabel wireGuardLabel = new LinkLabel();

                //Set the server name label (My Pi Server)
                serverName.Text = connInfo.name;
                serverName.Font = new Font("Segoe UI", 14, FontStyle.Bold);
                serverName.Size = new Size(200, 24);
                serverName.Location = new Point(40, 0);

                //Set the detail label (user@example.host.com)
                serverDetail.Text = $"{connInfo.user}@{connInfo.host}";
                serverDetail.Font = new Font("Segoe UI", 10, FontStyle.Regular);
                serverDetail.Size = new Size(200, 16);
                serverDetail.Location = new Point(47, 21);

                //Set the putty link label
                puttyLabel.Text = $"Console";
                puttyLabel.Font = new Font("Segoe UI", 9, FontStyle.Underline);
                puttyLabel.Size = new Size(52, 16);
                puttyLabel.Location = new Point(48, 37);

                //Set the edit link label
                wireGuardLabel.Text = $"WireGuard";
                wireGuardLabel.Font = new Font("Segoe UI", 9, FontStyle.Underline);
                wireGuardLabel.Size = new Size(64, 16);
                wireGuardLabel.Location = new Point(96, 37);

                //Set the host panel parameters
                p.Location = new Point(x, y);
                p.Size = new Size(256, 64);
                p.BorderStyle = BorderStyle.FixedSingle;

                //Set the server name label (My Pi Server)
                statusPoint.Text = "•";
                statusPoint.Font = new Font("Segoe UI", 40, FontStyle.Bold);
                statusPoint.Size = new Size(32, 64);
                statusPoint.Location = new Point(0, -16);
                statusPoint.ForeColor = Color.BlueViolet;

                //Add the controls
                p.Controls.Add(serverName);
                p.Controls.Add(serverDetail);
                p.Controls.Add(puttyLabel);
                p.Controls.Add(wireGuardLabel);
                p.Controls.Add(statusPoint);

                basePanel.Controls.Add(p);
                y += height;

                if (y == (height * cols))
                {
                    y = 0;
                    x += width;
                }

                wireGuardLabel.Click += new EventHandler(delegate (Object o, EventArgs a) 
                {
                    wirePanel.Visible = true;
                    wirePanelGroup.Text = connInfo.name + " WireGuard configuration";
                    closeConfiguratorBtn.Visible = true;
                    editConnBtn.Visible = false;
                    addConnBtn.Visible = false;
                    
                    loadVPNUsers(connInfo);
                    activeConnection = connInfo;
                });

                puttyLabel.Click += new EventHandler(delegate (Object o, EventArgs a) 
                {
                    System.Diagnostics.Process process = new System.Diagnostics.Process();
                    System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
                    startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                    startInfo.FileName = "cmd.exe";
                    startInfo.Arguments = $"/C wt ; ssh {connInfo.user}@{connInfo.host} -p {connInfo.port}";
                    process.StartInfo = startInfo;
                    process.Start();
                });

                new Thread(() => {
                    using (var client = new SshClient(connInfo.host, connInfo.port, connInfo.user, connInfo.pass))
                    {
                        try 
                        {
                            client.Connect();

                            if (client.ConnectionInfo.IsAuthenticated)
                            {
                                this.Invoke((MethodInvoker) (() => {
                                    statusPoint.ForeColor = Color.Green;
                                }));
                            }
                            else
                            {
                                this.Invoke((MethodInvoker) (() => {
                                    statusPoint.ForeColor = Color.Red;
                                }));
                            }

                            client.Disconnect();
                        }
                        catch (Exception ag)
                        {
                            this.Invoke((MethodInvoker) (() => {
                                statusPoint.ForeColor = Color.Red;
                            }));
                        }  
                    }
                }).Start();
            }
        }

        private void loadVPNUsers(ConnectionInfo connInfo)
        {
            using (var client = new SshClient(connInfo.host, connInfo.port, connInfo.user, connInfo.pass))
            {
                try 
                {
                    client.Connect();

                    if (client.ConnectionInfo.IsAuthenticated)
                    {
                        ShellStream stream = client.CreateShellStream("xterm", 80, 50, 1024, 1024, 1024);
                        SshCommand result = client.RunCommand($"echo {connInfo.pass} | sudo -S pivpn -c");

                        string pattern = @"^(?<user>[a-zA-Z0-9-_]*)\s*((?<remoteIp>\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b\:[0-9]{1,6})|\(none\))\s*(?<virtualIp>\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)\s*(?<received>[.a-zA-Z0-9]*)\s*(?<sent>[.a-zA-Z0-9]*)\s*((?<month>[a-zA-Z]{3})\s(?<day>[0-9]{2})\s(?<year>[0-9]{4})\s-\s(?<time>(?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d))|\(not yet\))";
                        RegexOptions options = RegexOptions.Multiline;

                        wireGuardListView.Items.Clear();

                        foreach (Match m in Regex.Matches(result.Result, pattern, options))
                        {
                            ListViewItem item = new ListViewItem();

                            item.Text = m.Groups[6].Value;
                            item.SubItems.Add(m.Groups[7].Value);
                            item.SubItems.Add(m.Groups[8].Value);
                            item.SubItems.Add(m.Groups[9].Value);
                            item.SubItems.Add(m.Groups[10].Value);
                            item.SubItems.Add($"{m.Groups[14].Value} {m.Groups[12].Value}-{m.Groups[11].Value}-{m.Groups[13].Value}");

                            wireGuardListView.Items.Add(item);
                        }
                    }

                    client.Disconnect();
                }
                catch (Exception)
                { }  
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            connTestResultLabel.Text = "Connecting ...";
            connTestResultLabel.ForeColor = Color.Black;
            enableUI(true, false);
            
            testThread = null;
            testThread = new Thread(() => {
                using (var client = new SshClient(hostTxt.Text, int.Parse(portText.Text), userText.Text, passText.Text))
                {
                    try 
                    {
                        client.Connect();

                        if (client.ConnectionInfo.IsAuthenticated)
                        {
                            this.Invoke((MethodInvoker) (() => {
                                connTestResultLabel.Text = "Success";
                                connTestResultLabel.ForeColor = Color.Green;
                                enableUI(false, true);
                            }));
                        }
                        else
                        {
                            this.Invoke((MethodInvoker) (() => {
                                connTestResultLabel.Text = "Incorrect credentials";
                                connTestResultLabel.ForeColor = Color.Orange;
                                enableUI(true);
                            }));
                        }

                        client.Disconnect();
                    }
                    catch (AggregateException ag)
                    {
                        this.Invoke((MethodInvoker) (() => {
                            connTestResultLabel.Text = ag.InnerException.Message;
                            connTestResultLabel.ForeColor = Color.Red;
                            enableUI(true);
                        }));
                    }       
                    catch (SocketException socex)
                    {
                        this.Invoke((MethodInvoker) (() => {
                            connTestResultLabel.Text = socex.Message;
                            connTestResultLabel.ForeColor = Color.Red;
                            enableUI(true);
                        }));
                    }    
                    catch (SshAuthenticationException)
                    {
                        this.Invoke((MethodInvoker) (() => {
                            connTestResultLabel.Text = "Incorrect credentials";
                            connTestResultLabel.ForeColor = Color.Orange;
                            enableUI(true);
                        }));
                    }   
                }
            });
            testThread.Start();
        }

        private void saveBtn_Click(object sender, EventArgs e)
        {
            ConnectionInfo conInfo = new ConnectionInfo();

            conInfo.name = serverNameText.Text;
            conInfo.host = hostTxt.Text;
            conInfo.port = int.Parse(portText.Text);
            conInfo.user = userText.Text;
            conInfo.pass = passText.Text;
            
            connections.Add(conInfo);
            File.WriteAllText(Environment.CurrentDirectory + "/connections.json", JsonConvert.SerializeObject(connections, Formatting.Indented));
            button3.PerformClick();
            ReloadUI();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            ReloadUI();
        }

        private void editConnBtn_Click(object sender, EventArgs e)
        {
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.FileName = "cmd.exe";
            startInfo.Arguments = $"/C {Environment.CurrentDirectory + "/connections.json"}";
            process.StartInfo = startInfo;
            process.Start();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            wirePanel.Visible = false;
            editConnBtn.Visible = true;
            addConnBtn.Visible = true;
            closeConfiguratorBtn.Visible = false;

            wireGuardListView.Items.Clear();
            wireGuardListView.Items.Add(new ListViewItem("Loading ..."));
        }

        private void addUserBtn_Click(object sender, EventArgs e)
        {
            addUserBtn.Enabled = false;
            userAddTxt.Enabled = false;

            new Thread(() => {
                using (var client = new SshClient(activeConnection.host, activeConnection.port, activeConnection.user, activeConnection.pass))
                {
                    try 
                    {
                        client.Connect();

                        if (client.ConnectionInfo.IsAuthenticated)
                        {
                            ShellStream stream = client.CreateShellStream("xterm", 80, 50, 1024, 1024, 1024);
                            SshCommand result = client.RunCommand($"echo {userAddTxt.Text} | sudo -S pivpn add");

                            string pattern = @"^(?<user>[a-zA-Z0-9-_]*)\s*((?<remoteIp>\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b\:[0-9]{1,6})|\(none\))\s*(?<virtualIp>\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)\s*(?<received>[.a-zA-Z0-9]*)\s*(?<sent>[.a-zA-Z0-9]*)\s*((?<month>[a-zA-Z]{3})\s(?<day>[0-9]{2})\s(?<year>[0-9]{4})\s-\s(?<time>(?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d))|\(not yet\))";
                            RegexOptions options = RegexOptions.Multiline;

                            wireGuardListView.Items.Clear();

                            foreach (Match m in Regex.Matches(result.Result, pattern, options))
                            {
                                ListViewItem item = new ListViewItem();

                                item.Text = m.Groups[6].Value;
                                item.SubItems.Add(m.Groups[7].Value);
                                item.SubItems.Add(m.Groups[8].Value);
                                item.SubItems.Add(m.Groups[9].Value);
                                item.SubItems.Add(m.Groups[10].Value);
                                item.SubItems.Add($"{m.Groups[14].Value} {m.Groups[12].Value}-{m.Groups[11].Value}-{m.Groups[13].Value}");


                                this.Invoke((MethodInvoker) (() => {
                                    wireGuardListView.Items.Add(item);
                                }));
                            }
                        }

                        client.Disconnect();
                    }
                    catch (Exception)
                    { }  
                }

                this.Invoke((MethodInvoker) (() => {
                    loadVPNUsers(activeConnection);
                    addUserBtn.Enabled = true;
                    userAddTxt.Enabled = true;
                    userAddTxt.Text = "";
                }));
            }).Start();
        }

        private void remSelectedBtn_Click(object sender, EventArgs e)
        {
            if (wireGuardListView.SelectedItems.Count > 0)
            {
                String text = wireGuardListView.SelectedItems[0].Text; 
                
            }
        }

        private void getSelUserBtn_Click(object sender, EventArgs e)
        {
            if (wireGuardListView.SelectedItems.Count > 0)
            {
                String text = wireGuardListView.SelectedItems[0].Text; 
                using (var sftp = new SftpClient(activeConnection.host, activeConnection.port, activeConnection.user, activeConnection.pass))
                {
                    sftp.Connect();

                    SaveFileDialog fileDiag = new SaveFileDialog();
                    fileDiag.Filter = "WireGuard config|*.conf";
                    fileDiag.FileName = $"{text}.conf";

                    DialogResult result = fileDiag.ShowDialog();
                    if (result == DialogResult.OK)
                    {
                        Stream file = File.OpenWrite(fileDiag.FileName);
                        sftp.DownloadFile($"/home/{activeConnection.user}/configs/{text}.conf", file);
                        MessageBox.Show($"Config file has been saved, you can now import this into WireGuard.");
                        file.Close();
                    }
                    sftp.Disconnect();
                }
            }
        }
    }
}
