import json
import pandas as pd
import os

class LogParser:
    def __init__(self, cowrie_log_path='logs/cowrie.json', http_log_path='logs/http_honeypot.json'):
        self.cowrie_log_path = cowrie_log_path
        self.http_log_path = http_log_path

    def parse_cowrie_logs(self):
        """Parses Cowrie JSON logs into a list of dictionaries."""
        parsed_data = []
        if not os.path.exists(self.cowrie_log_path):
            return parsed_data
            
        with open(self.cowrie_log_path, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    # Extract relevant fields
                    parsed_event = {
                        'timestamp': event.get('timestamp'),
                        'src_ip': event.get('src_ip'),
                        'eventid': event.get('eventid'),
                        'session': event.get('session_id'),
                        'username': event.get('username'),
                        'password': event.get('password'),
                        'command': event.get('command'),
                        'type': 'ssh'
                    }
                    parsed_data.append(parsed_event)
                except json.JSONDecodeError:
                    continue
        return parsed_data

    def parse_http_logs(self):
        """Parses HTTP honeypot JSON logs into a list of dictionaries."""
        parsed_data = []
        if not os.path.exists(self.http_log_path):
            return parsed_data

        with open(self.http_log_path, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    # Extract relevant fields
                    parsed_event = {
                        'timestamp': event.get('timestamp'),
                        'src_ip': event.get('src_ip'),
                        'eventid': event.get('eventid'),
                        'method': event.get('method'),
                        'path': event.get('path'),
                        'user_agent': event.get('user_agent'),
                        'form_data': json.dumps(event.get('form_data', {})),
                        'type': 'http'
                    }
                    parsed_data.append(parsed_event)
                except json.JSONDecodeError:
                    continue
        return parsed_data

    def get_combined_dataframe(self):
        """Combines SSH and HTTP logs into a single pandas DataFrame."""
        ssh_logs = self.parse_cowrie_logs()
        http_logs = self.parse_http_logs()
        
        df_ssh = pd.DataFrame(ssh_logs)
        df_http = pd.DataFrame(http_logs)
        
        # Combine dataframes
        combined_df = pd.concat([df_ssh, df_http], ignore_index=True)
        
        # Sort by timestamp if available
        if not combined_df.empty and 'timestamp' in combined_df.columns:
            combined_df['timestamp'] = pd.to_datetime(combined_df['timestamp'])
            combined_df = combined_df.sort_values(by='timestamp')
            
        return combined_df

    def analyze_sessions(self):
        """
        Reads Cowrie JSON logs, groups them by session ID, and calculates metrics
        for each session (IP, login attempts, command counts, duration, etc.).
        Returns a pandas DataFrame.
        """
        if not os.path.exists(self.cowrie_log_path):
            return pd.DataFrame()

        # Step 1: Read the file line by line and load as JSON objects
        events = []
        with open(self.cowrie_log_path, 'r') as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        
        if not events:
            return pd.DataFrame()

        # Step 2: Convert to DataFrame for easier grouping and manipulation
        df = pd.DataFrame(events)
        
        # Ensure timestamp is in datetime format for duration calculations
        df['timestamp'] = pd.to_datetime(df['timestamp'])

        # Step 3: Group by 'session' (or 'session_id' depending on Cowrie version)
        # Cowrie usually uses 'session' for event records, but our previous parser used 'session_id'
        # Let's ensure we use the actual key present in the JSON
        session_key = 'session' if 'session' in df.columns else 'session_id'
        
        session_groups = df.groupby(session_key)
        
        session_stats = []

        for session_id, group in session_groups:
            # Sort group by timestamp to ensure chronological order
            group = group.sort_values('timestamp')

            # Calculate metrics
            src_ip = group['src_ip'].iloc[0] if 'src_ip' in group.columns else None
            
            # Login attempts (events related to login)
            login_events = group[group['eventid'].str.contains('login', na=False)]
            login_attempts = len(login_events)

            # Command related metrics
            command_events = group[group['eventid'] == 'cowrie.command.input']
            commands_list = command_events['command'].tolist() if not command_events.empty else []
            command_count = len(commands_list)
            unique_commands = list(set(commands_list))

            # Session duration calculation (last event time - first event time)
            start_time = group['timestamp'].min()
            end_time = group['timestamp'].max()
            duration_seconds = (end_time - start_time).total_seconds()

            session_stats.append({
                'session_id': session_id,
                'src_ip': src_ip,
                'login_attempts': login_attempts,
                'command_count': command_count,
                'commands': commands_list,
                'unique_commands': unique_commands,
                'duration_seconds': duration_seconds
            })

        # Step 4: Return as a consolidated pandas DataFrame
        return pd.DataFrame(session_stats)

if __name__ == "__main__":
    parser = LogParser()
    
    # Test session analysis
    print("--- Session Analysis ---")
    session_df = parser.analyze_sessions()
    if not session_df.empty:
        print(f"Analyzed {len(session_df)} unique sessions.")
        print(session_df[['session_id', 'src_ip', 'login_attempts', 'command_count', 'duration_seconds']].head())
    
    # Existing combined test
    print("\n--- Combined Logs ---")
    df = parser.get_combined_dataframe()
    print(f"Parsed {len(df)} log entries.")
    
    # Save combined logs to attack_logs.csv
    output_path = 'data/attack_logs.csv'
    df.to_csv(output_path, index=False)
    print(f"Successfully saved combined logs to {output_path}")
    
    if not df.empty:
        print(df.head())
