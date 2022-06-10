using System.Collections;
using System.Xml;

namespace System.Security.Cryptography.Xml;
internal class CanonicalXmlNodeList : XmlNodeList, IList
{
	private readonly ArrayList _nodeArray;

	internal CanonicalXmlNodeList()
	{
		_nodeArray = new ArrayList();
	}

	public override XmlNode Item(int index) => (XmlNode)_nodeArray[index];

	public override IEnumerator GetEnumerator() => _nodeArray.GetEnumerator();

	public override int Count => _nodeArray.Count;

	// IList methods
	public int Add(object value)
	{
		if (value is not XmlNode)
		{
			throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "node");
		}

		return _nodeArray.Add(value);
	}

	public void Clear() => _nodeArray.Clear();

	public bool Contains(object value) => _nodeArray.Contains(value);

	public int IndexOf(object value) => _nodeArray.IndexOf(value);

	public void Insert(int index, object value)
	{
		if (value is not XmlNode)
		{
			throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "value");
		}

		_nodeArray.Insert(index, value);
	}

	public void Remove(object value) => _nodeArray.Remove(value);

	public void RemoveAt(int index) => _nodeArray.RemoveAt(index);

	public bool IsFixedSize => _nodeArray.IsFixedSize;

	public bool IsReadOnly => _nodeArray.IsReadOnly;

	object IList.this[int index]
	{
		get => _nodeArray[index];
		set
		{
			if (value is not XmlNode)
			{
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "value");
			}

			_nodeArray[index] = value;
		}
	}

	public void CopyTo(Array array, int index) => _nodeArray.CopyTo(array, index);

	public object SyncRoot => _nodeArray.SyncRoot;

	public bool IsSynchronized => _nodeArray.IsSynchronized;
}
