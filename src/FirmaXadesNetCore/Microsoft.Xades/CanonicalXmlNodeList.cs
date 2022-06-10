namespace System.Security.Cryptography.Xml;

using System;
using System.Collections;
using System.Xml;

internal class CanonicalXmlNodeList : XmlNodeList, IList
{
	private ArrayList m_nodeArray;

	internal CanonicalXmlNodeList()
	{
		m_nodeArray = new ArrayList();
	}

	public override XmlNode Item(int index)
	{
		return (XmlNode)m_nodeArray[index];
	}

	public override IEnumerator GetEnumerator()
	{
		return m_nodeArray.GetEnumerator();
	}

	public override int Count
	{
		get { return m_nodeArray.Count; }
	}

	// IList methods
	public int Add(object value)
	{
		if (!(value is XmlNode))
			throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "node");
		return m_nodeArray.Add(value);
	}

	public void Clear()
	{
		m_nodeArray.Clear();
	}

	public bool Contains(object value)
	{
		return m_nodeArray.Contains(value);
	}

	public int IndexOf(object value)
	{
		return m_nodeArray.IndexOf(value);
	}

	public void Insert(int index, object value)
	{
		if (!(value is XmlNode))
			throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "value");
		m_nodeArray.Insert(index, value);
	}

	public void Remove(object value)
	{
		m_nodeArray.Remove(value);
	}

	public void RemoveAt(int index)
	{
		m_nodeArray.RemoveAt(index);
	}

	public bool IsFixedSize
	{
		get { return m_nodeArray.IsFixedSize; }
	}

	public bool IsReadOnly
	{
		get { return m_nodeArray.IsReadOnly; }
	}

	object IList.this[int index]
	{
		get { return m_nodeArray[index]; }
		set
		{
			if (!(value is XmlNode))
				throw new ArgumentException(SecurityResources.GetResourceString("Cryptography_Xml_IncorrectObjectType"), "value");
			m_nodeArray[index] = value;
		}
	}

	public void CopyTo(Array array, int index)
	{
		m_nodeArray.CopyTo(array, index);
	}

	public object SyncRoot
	{
		get { return m_nodeArray.SyncRoot; }
	}

	public bool IsSynchronized
	{
		get { return m_nodeArray.IsSynchronized; }
	}
}
