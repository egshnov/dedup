import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

CHUNK_SIZE = 4096  
PLOT_STYLE = 'seaborn-v0_8'
plt.style.use(PLOT_STYLE)

# Sample data (replace with your actual numbers)
data = {
    'Distribution': ['Ubuntu Server 24.04', 'CentOS 8.4', 'Debian 12.0', 'Fedora 39'],
    'total_lbn': [794000, 459008, 743200, 1129904],
    'unique_pbn': [651529, 346561, 541537, 1014439]
}

df = pd.DataFrame(data)

df['dedup_ratio'] = df['total_lbn'] / df['unique_pbn']
df['saved_blocks'] = df['total_lbn'] - df['unique_pbn']
df['saved_space_gb'] = (df['saved_blocks'] * CHUNK_SIZE) / (1024**3)

plt.figure(figsize=(8, 6))
sns.barplot(x='Distribution', y='dedup_ratio', data=df, palette='viridis')
plt.title('Deduplication Ratio Comparison')
plt.ylabel('Ratio (total_lbn/unique_pbn)')
plt.xlabel('Distribution')
plt.grid(True, linestyle='--', alpha=0.7)
plt.tight_layout()
plt.savefig('dedup_ratio.pdf', dpi=300, format='pdf')
plt.close()

plt.figure(figsize=(8, 6))
sns.barplot(x='Distribution', y='saved_space_gb', data=df, palette='magma')
plt.title('Saved Storage Space')
plt.ylabel('Saved Space (GB)')
plt.xlabel('Distribution')
plt.grid(True, linestyle='--', alpha=0.7)
plt.tight_layout()
plt.savefig('saved_space.pdf', dpi=300, format='pdf')
plt.close()

print("Diagrams saved as:")
print("- dedup_ratio.pdf")
print("- saved_space.pdf")