using System;
using System.Management;

namespace MVA.ConsoleApp
{
    class RenamingComputer
    {
        private class Type
        {
            public static String success = "success";
            public static String information = "information";
            public static String error = "error";
        }

        static void Main(string[] args)
        {

            Rename();

            Console.WriteLine("Для продолжения нажмите любую клавишу...");
            Console.ReadKey();
        }

        private static void Rename()
        {
            String serialNumber = String.Empty;
            SelectQuery query = new SelectQuery("Select * from win32_bios");
            ManagementObjectSearcher searcher = null;
            try
            {
                searcher = new ManagementObjectSearcher(query);
                foreach (ManagementObject item in searcher.Get())
                {
                    serialNumber = item["SerialNumber"].ToString();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            Console.WriteLine(serialNumber);

            //serialNumber = "Mac-" + serialNumber.Substring(serialNumber.Length - 11).ToUpper();
            serialNumber = "MAC-80VVF8QM";

            Console.WriteLine(serialNumber);
            query = new SelectQuery("Select * from Win32_ComputerSystem");
            try
            {
                searcher = new ManagementObjectSearcher(query);
                foreach (ManagementObject item in searcher.Get())
                {
                    item["Name"] = serialNumber;
                    Console.WriteLine(item["Name"]);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message); ;
            }

            Console.WriteLine();
        }

        private static void PrintMessage(string messageText, string messageType)
        {
            #region Метод для печати сообщений
            switch (messageType)
            {
                case "success":
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine(messageText);
                    Console.ResetColor();
                    Console.WriteLine();
                    break;
                case "information":
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(new string('-', 70));
                    Console.WriteLine(messageText);
                    Console.WriteLine(new string('-', 70));
                    Console.ResetColor();
                    Console.WriteLine();
                    break;
                case "error":
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(messageText);
                    Console.ResetColor();
                    Console.WriteLine();
                    break;
                default:
                    Console.WriteLine(messageText);
                    Console.WriteLine();
                    break;
            }
            #endregion
        }

    }
}
